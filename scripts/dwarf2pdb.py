#!/usr/bin/env python3
"""
dwarf2pdb.py - Generate a PDB (public symbols) from a MinGW/GCC PE executable.

The PDB contains:
  - All public symbols (functions + global data) with their addresses
  - Section layout so WinDbg/ReactOS debugger can map RVAs to symbols

Requires:
  - Python 3.6+
  - pefile  (pip3 install pefile)
  - nm (from binutils-mingw-w64) or llvm-nm

Usage:
  python3 dwarf2pdb.py <input.exe> <output.pdb>
"""
import sys, os, re, struct, subprocess, uuid, hashlib

# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------
NM_CANDIDATES = [
    "i686-w64-mingw32-nm", "x86_64-w64-mingw32-nm",
    "llvm-nm-18", "llvm-nm-17", "llvm-nm-16", "llvm-nm", "nm",
]

def find_tool(names):
    for n in names:
        try:
            subprocess.check_call(["which", n], stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
            return n
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
    return None

# ---------------------------------------------------------------------------
# Symbol extraction
# ---------------------------------------------------------------------------
def get_symbols(exe_path, nm):
    raw = subprocess.check_output([nm, "--demangle", exe_path],
                                  stderr=subprocess.DEVNULL, timeout=120)
    syms = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        m = re.match(r'^([0-9a-fA-F]+)\s+([TtWwDdBbRrGg])\s+(.+)$', line)
        if m:
            addr = int(m.group(1), 16)
            kind = m.group(2)
            name = m.group(3).strip()
            if addr > 0 and name and len(name) < 4096:
                is_func = kind.upper() in ('T', 'W')
                syms.append((addr, name, is_func))
    # Sort by address
    syms.sort(key=lambda x: x[0])
    return syms

# ---------------------------------------------------------------------------
# PE section reading
# ---------------------------------------------------------------------------
def get_pe_sections(exe_path):
    try:
        import pefile
        pe = pefile.PE(exe_path, fast_load=True)
        secs = []
        for s in pe.sections:
            secs.append({
                "name":          s.Name.rstrip(b'\x00').decode("ascii", errors="replace"),
                "rva":           s.VirtualAddress,
                "size_raw":      s.SizeOfRawData,
                "size_virt":     s.Misc_VirtualSize,
                "chars":         s.Characteristics,
                "raw_offset":    s.PointerToRawData,
            })
        image_base = pe.OPTIONAL_HEADER.ImageBase
        pe.close()
        return secs, image_base
    except ImportError:
        # Fallback: parse PE headers manually
        with open(exe_path, "rb") as f:
            data = f.read()
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        sig = data[e_lfanew:e_lfanew+4]
        assert sig == b'PE\x00\x00'
        coff_off = e_lfanew + 4
        num_secs = struct.unpack_from('<H', data, coff_off + 2)[0]
        opt_size = struct.unpack_from('<H', data, coff_off + 16)[0]
        image_base = struct.unpack_from('<I', data, coff_off + 20 + 28)[0]
        sec_off = coff_off + 20 + opt_size
        secs = []
        for i in range(num_secs):
            o = sec_off + i * 40
            name = data[o:o+8].rstrip(b'\x00').decode("ascii", errors="replace")
            virt_sz   = struct.unpack_from('<I', data, o + 8)[0]
            rva        = struct.unpack_from('<I', data, o + 12)[0]
            raw_sz     = struct.unpack_from('<I', data, o + 16)[0]
            raw_off    = struct.unpack_from('<I', data, o + 20)[0]
            chars      = struct.unpack_from('<I', data, o + 36)[0]
            secs.append({"name": name, "rva": rva,
                         "size_raw": raw_sz, "size_virt": max(virt_sz, 1),
                         "chars": chars, "raw_offset": raw_off})
        return secs, image_base

def rva_to_seg_off(rva, sections):
    for i, s in enumerate(sections):
        if s["rva"] <= rva < s["rva"] + max(s.get("size_virt", 1), 1):
            return i + 1, rva - s["rva"]
    return None, None

# ---------------------------------------------------------------------------
# MSF (Multi-Stream File) writer
# ---------------------------------------------------------------------------
BLOCK_SIZE = 4096
MSF_MAGIC  = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00"

def build_msf(stream_data_list):
    """
    stream_data_list: list of bytes, one per stream (index = stream number).
    Returns the complete MSF file as bytes.
    """
    block_allocs = {}   # block_no -> bytes
    next_block = [3]    # 0=super, 1=fpm1, 2=fpm2

    def alloc(data):
        addrs = []
        for i in range(0, max(len(data), 1), BLOCK_SIZE):
            chunk = data[i:i+BLOCK_SIZE]
            chunk += b'\x00' * (BLOCK_SIZE - len(chunk))
            n = next_block[0]
            block_allocs[n] = chunk
            addrs.append(n)
            next_block[0] += 1
        return addrs

    stream_blocks = [alloc(s) for s in stream_data_list]

    # Directory stream: NumStreams + StreamSizes[] + BlockLists[]
    dir_data  = struct.pack('<I', len(stream_data_list))
    dir_data += b''.join(struct.pack('<I', len(s)) for s in stream_data_list)
    dir_data += b''.join(struct.pack('<I', b)
                         for blist in stream_blocks for b in blist)

    dir_blocks = alloc(dir_data)

    # Block map (directory of the directory)
    bmap_data   = b''.join(struct.pack('<I', b) for b in dir_blocks)
    bmap_blocks = alloc(bmap_data)
    assert len(bmap_blocks) == 1, "block map too big"

    total_blocks = next_block[0]

    # Superblock
    sb  = MSF_MAGIC
    sb += struct.pack('<I', BLOCK_SIZE)
    sb += struct.pack('<I', 1)              # FreeBlockMapBlock
    sb += struct.pack('<I', total_blocks)
    sb += struct.pack('<I', len(dir_data))  # NumDirectoryBytes
    sb += struct.pack('<I', 0)
    sb += struct.pack('<I', bmap_blocks[0])
    sb += b'\x00' * (BLOCK_SIZE - len(sb))

    # FPM block 1: mark used blocks as not-free (clear bit)
    fpm = bytearray(b'\xff' * BLOCK_SIZE)
    for b in range(total_blocks):
        fpm[b >> 3] &= ~(1 << (b & 7))
    # keep unused bits beyond total_blocks as 0xff
    fpm = bytes(fpm)
    fpm2 = b'\xff' * BLOCK_SIZE

    # Assemble file
    all_blocks = {0: sb, 1: fpm, 2: fpm2}
    all_blocks.update(block_allocs)
    out = bytearray()
    for i in range(total_blocks):
        out += all_blocks[i]
    return bytes(out)

# ---------------------------------------------------------------------------
# PDB Info Stream (stream 1)
# ---------------------------------------------------------------------------
PDB_VERSION_VC70 = 20000404

def _build_named_stream_map(entries):
    """
    Serialise a {name_str: stream_index} dict as a NamedStreamMap.

    Wire format (from LLVM NamedStreamMap / HashTable):
      uint32  StringBufferSize
      bytes   string buffer (concatenated null-terminated strings)
      uint32  HashTable.Size     (= number of entries)
      uint32  HashTable.Capacity (>= 2 × Size, must be > 0)
      uint32  Present.NumWords   + Present.Words[]
      uint32  Deleted.NumWords   (always 0 for a fresh table)
      For each present bucket (in order):
        uint32 key   (byte offset of name in string buffer)
        uint32 value (stream index)
    """
    # Build string buffer
    strbuf = b''
    offsets = {}
    for name in entries:
        offsets[name] = len(strbuf)
        strbuf += name.encode() + b'\x00'

    n = len(entries)
    # Choose capacity = next power-of-two >= 2*n (minimum 2)
    cap = 2
    while cap < n * 2:
        cap <<= 1

    # Assign buckets: key (string offset) % capacity
    buckets = {}
    for name, stream_idx in entries.items():
        key = offsets[name]
        b = key % cap
        while b in buckets:          # linear probe on collision
            b = (b + 1) % cap
        buckets[b] = (key, stream_idx)

    # Present bitvector: one bit per bucket
    last_present = max(buckets.keys()) if buckets else 0
    num_words = (last_present // 32) + 1
    words = [0] * num_words
    for b in buckets:
        words[b // 32] |= (1 << (b % 32))

    data  = struct.pack('<I', len(strbuf))       # StringBufferSize
    data += strbuf
    data += struct.pack('<I', n)                  # HashTable.Size
    data += struct.pack('<I', cap)                # HashTable.Capacity
    data += struct.pack('<I', num_words)          # Present.NumWords
    data += struct.pack(f'<{num_words}I', *words) # Present.Words
    data += struct.pack('<I', 0)                  # Deleted.NumWords = 0
    for b in sorted(buckets):
        key, val = buckets[b]
        data += struct.pack('<II', key, val)
    return data

def build_pdb_stream(guid_bytes, names_stream_idx, age=1):
    """PDB info stream (stream 1): header + named stream map + feature flags."""
    nmap = _build_named_stream_map({"/names": names_stream_idx})

    data  = struct.pack('<I', PDB_VERSION_VC70)
    data += struct.pack('<I', 0)       # Signature (timestamp, 0 = unknown)
    data += struct.pack('<I', age)
    data += guid_bytes                 # GUID (16 bytes)
    data += nmap                       # named stream map (no preceding size field)
    data += struct.pack('<I', 0x20)    # feature flags: VC140 compatible
    return data

# ---------------------------------------------------------------------------
# TPI / IPI Stream (streams 2 and 4) -- empty type info
# ---------------------------------------------------------------------------
TPI_VERSION_V80 = 20040203

def build_tpi_stream():
    TI_BEGIN = 0x1000
    hdr  = struct.pack('<I', TPI_VERSION_V80)  # Version
    hdr += struct.pack('<I', 56)               # HeaderSize
    hdr += struct.pack('<I', TI_BEGIN)         # TypeIndexBegin
    hdr += struct.pack('<I', TI_BEGIN)         # TypeIndexEnd (no types)
    hdr += struct.pack('<I', 0)               # TypeRecordBytes
    hdr += struct.pack('<HH', 0xFFFF, 0xFFFF) # HashStreamIndex, HashAuxStreamIndex
    hdr += struct.pack('<I', 4)               # HashKeySize
    hdr += struct.pack('<I', 0x3FFFF)         # NumHashBuckets
    hdr += struct.pack('<iI', 0, 0)           # HashValueBuffer (off, len)
    hdr += struct.pack('<iI', 0, 0)           # IndexOffsetBuffer (off, len)
    hdr += struct.pack('<iI', 0, 0)           # HashAdjBuffer (off, len)
    return hdr

# ---------------------------------------------------------------------------
# Section headers stream (used by DBI)
# ---------------------------------------------------------------------------
def build_section_headers_stream(sections):
    """Write IMAGE_SECTION_HEADER entries (40 bytes each)."""
    data = b''
    for s in sections:
        name_bytes = s["name"].encode("ascii", errors="replace")[:8]
        name_bytes = name_bytes + b'\x00' * (8 - len(name_bytes))
        data += name_bytes
        data += struct.pack('<I', s.get("size_virt", 0))
        data += struct.pack('<I', s["rva"])
        data += struct.pack('<I', s.get("size_raw", 0))
        data += struct.pack('<I', s.get("raw_offset", 0))
        data += struct.pack('<I', 0)   # PointerToRelocations
        data += struct.pack('<I', 0)   # PointerToLinenumbers
        data += struct.pack('<H', 0)   # NumberOfRelocations
        data += struct.pack('<H', 0)   # NumberOfLinenumbers
        data += struct.pack('<I', s["chars"])
    return data

# ---------------------------------------------------------------------------
# Symbol record encoding (CodeView)
# ---------------------------------------------------------------------------
S_PUB32 = 0x110E

def encode_pub32(name, offset, segment, is_func):
    name_bytes = name.encode("utf-8", errors="replace") + b'\x00'
    flags = 2 if is_func else 0   # cvpsfFunction = 2
    # S_PUB32 payload: Flags(4) + Offset(4) + Segment(2) + Name[]
    rec = struct.pack('<IIH', flags, offset, segment) + name_bytes
    # Pad record to 4-byte boundary
    pad_len = (4 - (len(rec) % 4)) % 4
    rec += b'\xf4\xf3\xf2\xf1'[:pad_len]  # CV padding bytes
    size = len(rec) + 2   # +2 for the 'kind' field
    return struct.pack('<H', size) + struct.pack('<H', S_PUB32) + rec

# ---------------------------------------------------------------------------
# GSI (Global Symbol Info) streams
#
# Stream layout for public symbols:
#   Stream PUB_HASH  (= stream 7 in our layout):
#     PublicsStreamHeader (28 bytes)
#     GSI hash table (VerSig + VerHdr + HrSize + NumBuckets + HRs + bitmap + buckets)
#     AddrMap (uint32[] sorted by address, values = byte offsets into SYM_REC stream)
#   Stream SYM_REC   (= stream 8 in our layout):
#     Concatenated raw S_PUB32 CodeView records
#
# The GSI hash table structure (IPHR_HASH = 4096 buckets):
#   GSIHashHeader { VerSig=0xFFFFFFFF, VerHdr=0xf12f091a, HrSize, NumBuckets }
#   HashRecords[HrSize/8] { int32 offset_1based, int32 cRef=1 }
#   Bitmap  alignTo(IPHR_HASH+1, 32)/8 = 516 bytes  (1 bit per bucket)
#   NonEmptyBucketOffsets  M×4 bytes  (one uint32 per non-empty bucket, byte offset
#                                      of that bucket's LAST HR in the HR array)
# ---------------------------------------------------------------------------
IPHR_HASH       = 4096
GSI_VER_SIG     = 0xFFFFFFFF
GSI_VER_HDR     = 0xeffe0000 + 19990810   # = 0xf12f091a
BITMAP_BYTES    = ((IPHR_HASH + 1 + 31) // 32) * 4   # = 516

def _gsi_hash(name):
    """Microsoft GSI name hash (same as LLVM hashBufferV8)."""
    h = 0
    for c in name.lower().encode("utf-8", errors="replace"):
        h = (h * 0x1003F + c) & 0xFFFFFFFF
    return h % IPHR_HASH

def build_sym_rec_stream(symbols):
    """
    Build the symbol records stream (stream 8): raw S_PUB32 bytes.
    Returns (stream_bytes, list_of_(rva, sym_rec_offset)).
    """
    buf = b''
    offsets = []   # (rva, byte_offset_in_buf)
    for (rva, name, is_func) in symbols:
        seg, off = rva_to_seg_off_global(rva)
        if seg is None:
            continue
        rec_off = len(buf)
        buf += encode_pub32(name, off, seg, is_func)
        offsets.append((rva, name, rec_off))
    return buf, offsets

def build_pub_hash_stream(sym_entries, sym_rec_stream_len):
    """
    Build the public symbol hash stream (stream 7).
    sym_entries: list of (rva, name, rec_offset_in_symrec_stream)
    Returns stream bytes.
    """
    # Hash records: group by bucket, sorted by bucket index
    bucket_map = {}     # bucket_idx -> [rec_offset (1-based)]
    for (rva, name, rec_off) in sym_entries:
        b = _gsi_hash(name)
        bucket_map.setdefault(b, []).append(rec_off + 1)   # 1-based

    # Build HR array: sorted by bucket index
    hr_bytes = b''
    # Track the byte offset of the LAST HR in each bucket (for the bucket array)
    bucket_end_offset = {}   # bucket_idx -> byte offset of last HR (cumulative)
    cur_hr_off = 0
    for b_idx in sorted(bucket_map):
        chain = bucket_map[b_idx]
        for rec_off in chain:
            hr_bytes += struct.pack('<ii', rec_off, 1)
            cur_hr_off += 8
        # End offset = byte offset AFTER the last HR in this chain
        bucket_end_offset[b_idx] = cur_hr_off

    # Bitmap: 516 bytes, 1 bit per bucket
    bitmap = bytearray(BITMAP_BYTES)
    for b_idx in bucket_map:
        bitmap[b_idx >> 3] |= (1 << (b_idx & 7))

    # Bucket array: one uint32 per non-empty bucket (in bucket-index order)
    # Value = cumulative byte offset through HR array up to the END of this bucket
    buck_arr = b''
    for b_idx in sorted(bucket_end_offset):
        buck_arr += struct.pack('<I', bucket_end_offset[b_idx])

    gsi_hdr = struct.pack('<IIII',
                          GSI_VER_SIG, GSI_VER_HDR,
                          len(hr_bytes),
                          BITMAP_BYTES + len(buck_arr))

    gsi_data = gsi_hdr + hr_bytes + bytes(bitmap) + buck_arr

    # AddrMap: rec offsets into sym_rec stream, sorted by address
    addr_sorted = sorted(sym_entries, key=lambda e: e[0])
    addr_map = b''.join(struct.pack('<I', e[2]) for e in addr_sorted)

    # PublicsStreamHeader (28 bytes)
    pub_hdr = struct.pack('<IIII',
                          len(gsi_data),   # SymHash  = size of GSI hash blob
                          len(addr_map),   # AddrMap  = size of addr map blob
                          0,               # NumThunks
                          0)               # SizeOfThunk
    pub_hdr += struct.pack('<HH', 0xFFFF, 0)  # ISectThunkTable + Padding
    pub_hdr += struct.pack('<II', 0, 0)       # OffThunkTable + NumSections

    return pub_hdr + gsi_data + addr_map

def build_glob_hash_stream():
    """Empty global symbol hash stream."""
    gsi_hdr = struct.pack('<IIII',
                          GSI_VER_SIG, GSI_VER_HDR,
                          0,              # HrSize = 0
                          BITMAP_BYTES)   # NumBuckets = just the bitmap
    bitmap = b'\x00' * BITMAP_BYTES
    return gsi_hdr + bitmap

# Global section list for rva_to_seg_off used in builders
_SECTIONS = []

def rva_to_seg_off_global(rva):
    return rva_to_seg_off(rva, _SECTIONS)

# ---------------------------------------------------------------------------
# DBI Stream builder
# ---------------------------------------------------------------------------
DBI_VERSION_V70 = 19990903
MACHINE_x86     = 0x014C

def build_dbi_stream(sections, pub_stream_idx, glob_stream_idx,
                     sym_record_stream_idx, sec_hdr_stream_idx, age=1):
    """Build the DBI (Debug Info) stream."""

    # --- Module info substream (one fake module entry for the exe) ---
    mod_name = b"gtk-gnutella.exe\x00"
    obj_name = b"\x00"
    modi_raw = mod_name + obj_name
    # Pad to 4-byte boundary
    modi_raw += b'\x00' * ((4 - len(modi_raw) % 4) % 4)

    # Section contribution record v2 (header + one entry per section)
    SC_SIG_V2   = 0xF13151E4
    sc_data = struct.pack('<I', SC_SIG_V2)
    for i, s in enumerate(sections):
        # SectionContribEntry: ISect(2)+Off(4)+Size(4)+Chars(4)+Imod(2)+DataCrc(4)+RelocCrc(4)
        sc_data += struct.pack('<HxxIIIHxxII',
                               i + 1,            # ISect (1-based)
                               0,                # Off
                               s.get("size_virt", 0),
                               s["chars"],
                               1,                # Imod (module 0 owns everything)
                               0,                # DataCrc
                               0)                # RelocCrc

    # Section map substream
    nsecs = len(sections)
    # SectionMapHeader: Count + Log (both = nsecs)
    sec_map_data = struct.pack('<HH', nsecs, nsecs)
    for i, s in enumerate(sections):
        is_exec = bool(s["chars"] & 0x20000000)
        flags = 0x10d if is_exec else 0x109
        # SectionMapEntry: Flags(2)+Ovl(2)+Group(2)+Frame(2)+SectionName(2)+ClassName(2)
        #                  Offset(4)+SectionLength(4)
        sec_map_data += struct.pack('<HHHHHH II',
                                    flags,   # Flags
                                    0,       # Ovl
                                    0,       # Group
                                    i + 1,   # Frame (1-based)
                                    0xFFFF,  # SectionName (invalid)
                                    0xFFFF,  # ClassName (invalid)
                                    0,       # Offset
                                    s.get("size_virt", 0))

    # Source info substream (empty)
    # OptionalDbgHeader: series of uint16_t stream indices, -1 = not present
    # Slots: FPO, Exception, Fixup, OmapToSrc, OmapFromSrc, SectionHdr, TokenRIDMap,
    #        Xdata, Pdata, NewFPO, SectionHdrOrig
    INVALID = 0xFFFF
    opt_dbg  = struct.pack('<HHHHHHHHHHH',
                            INVALID,           # FPO
                            INVALID,           # Exception
                            INVALID,           # Fixup
                            INVALID,           # OmapToSrc
                            INVALID,           # OmapFromSrc
                            sec_hdr_stream_idx,# SectionHdr
                            INVALID,           # TokenRIDMap
                            INVALID,           # Xdata
                            INVALID,           # Pdata
                            INVALID,           # NewFPO
                            INVALID)           # SectionHdrOrig

    # MODI_T for module 0
    # Layout: SC_Record(16) + Flags(2) + ModiStreamIndex(2) + SymByteSize(4)
    #         + C11ByteSize(4) + C13ByteSize(4) + SourceFileCount(2) + Pad(2)
    #         + FileNameOffsets(4) + SrcFileNameNI(4) + PdbFilePathNI(4)
    #         + ModuleName[] + ObjFileName[]
    sc_rec = struct.pack('<HxxIIIHxxII', 1, 0,
                         sections[0].get("size_virt", 0) if sections else 0,
                         sections[0]["chars"] if sections else 0,
                         1, 0, 0)  # same as first section contrib
    modi_entry  = sc_rec
    modi_entry += struct.pack('<HH', 0, sym_record_stream_idx)  # Flags, ModiStreamIndex
    modi_entry += struct.pack('<III', 0, 0, 0)  # SymByteSize, C11, C13
    modi_entry += struct.pack('<HH', 0, 0)      # NumFiles, Pad
    modi_entry += struct.pack('<III', 0, 0, 0)  # FileNameOffsets, SrcFileNI, PdbFileNI
    modi_entry += mod_name + obj_name
    # Pad to 4 bytes
    pad = (4 - len(modi_entry) % 4) % 4
    modi_entry += b'\x00' * pad

    # DBI header
    mod_info_size  = len(modi_entry)
    sec_cont_size  = len(sc_data)
    sec_map_size   = len(sec_map_data)
    src_info_size  = 0
    ts_map_size    = 0
    opt_dbg_size   = len(opt_dbg)
    ec_size        = 0

    dbi_hdr  = struct.pack('<i',  -1)                   # VersionSignature
    dbi_hdr += struct.pack('<I',  DBI_VERSION_V70)
    dbi_hdr += struct.pack('<I',  age)
    dbi_hdr += struct.pack('<H',  glob_stream_idx)      # GlobalStreamIndex
    dbi_hdr += struct.pack('<H',  0x8000)               # BuildNumber (link-compatible)
    dbi_hdr += struct.pack('<H',  pub_stream_idx)       # PublicStreamIndex
    dbi_hdr += struct.pack('<H',  0)                    # PdbDllVersion
    dbi_hdr += struct.pack('<H',  sym_record_stream_idx)# SymRecordStream
    dbi_hdr += struct.pack('<H',  0)                    # PdbDllRbld
    dbi_hdr += struct.pack('<i',  mod_info_size)
    dbi_hdr += struct.pack('<i',  sec_cont_size)
    dbi_hdr += struct.pack('<i',  sec_map_size)
    dbi_hdr += struct.pack('<i',  src_info_size)
    dbi_hdr += struct.pack('<i',  ts_map_size)
    dbi_hdr += struct.pack('<I',  0)                    # MFCTypeServerIndex
    dbi_hdr += struct.pack('<i',  opt_dbg_size)
    dbi_hdr += struct.pack('<i',  ec_size)
    dbi_hdr += struct.pack('<H',  0)                    # Flags
    dbi_hdr += struct.pack('<H',  MACHINE_x86)
    dbi_hdr += struct.pack('<I',  0)                    # Padding

    return (dbi_hdr + modi_entry + sc_data + sec_map_data +
            b'\x00' * src_info_size + opt_dbg)

# ---------------------------------------------------------------------------
# Main PDB assembler
# ---------------------------------------------------------------------------
def build_pdb(exe_path, symbols, sections, image_base):
    global _SECTIONS
    _SECTIONS = sections

    guid_bytes = uuid.uuid4().bytes

    # Stream layout:
    # 0: old MSF directory (empty)
    # 1: PDB info stream
    # 2: TPI stream
    # 3: DBI stream
    # 4: IPI stream
    # 5: (unused placeholder — keeps stream indices matching lld convention)
    # 6: Global symbol hash stream
    # 7: Public symbol hash stream  ← PublicsStreamHeader + GSI + AddrMap
    # 8: Symbol records stream      ← raw S_PUB32 bytes
    # 9: /names stream
    # 10: Section headers stream

    GLOB_STREAM_IDX = 6
    PUB_STREAM_IDX  = 7
    SYM_REC_IDX     = 8
    NAMES_IDX       = 9
    SEC_HDR_IDX     = 10

    pdb_stream     = build_pdb_stream(guid_bytes, NAMES_IDX)
    tpi_stream     = build_tpi_stream()
    ipi_stream     = build_tpi_stream()

    sym_rec_stream, sym_entries = build_sym_rec_stream(symbols)
    pub_hash_stream = build_pub_hash_stream(sym_entries, len(sym_rec_stream))
    glob_hash_stream = build_glob_hash_stream()

    sec_hdr_stream = build_section_headers_stream(sections)
    names_stream   = struct.pack('<II', 0xEFFEEFFE, 1)   # sig + version

    dbi_stream = build_dbi_stream(sections,
                                   PUB_STREAM_IDX, GLOB_STREAM_IDX,
                                   SYM_REC_IDX, SEC_HDR_IDX)

    streams = [
        b'',               # 0: old dir
        pdb_stream,        # 1: PDB info
        tpi_stream,        # 2: TPI
        dbi_stream,        # 3: DBI
        ipi_stream,        # 4: IPI
        b'',               # 5: unused
        glob_hash_stream,  # 6: global hash
        pub_hash_stream,   # 7: public hash
        sym_rec_stream,    # 8: symbol records
        names_stream,      # 9: /names
        sec_hdr_stream,    # 10: section headers
    ]

    return build_msf(streams)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input.exe> <output.pdb>", file=sys.stderr)
        sys.exit(1)

    exe_path = sys.argv[1]
    pdb_path = sys.argv[2]

    nm = find_tool(NM_CANDIDATES)
    if not nm:
        print("ERROR: no nm tool found; install binutils-mingw-w64 or llvm", file=sys.stderr)
        sys.exit(1)

    print(f"[dwarf2pdb] exe    : {exe_path}")
    print(f"[dwarf2pdb] nm     : {nm}")

    syms = get_symbols(exe_path, nm)
    print(f"[dwarf2pdb] symbols: {len(syms)}")

    sections, image_base = get_pe_sections(exe_path)
    print(f"[dwarf2pdb] sections: {len(sections)}")

    pdb_bytes = build_pdb(exe_path, syms, sections, image_base)

    with open(pdb_path, 'wb') as f:
        f.write(pdb_bytes)

    print(f"[dwarf2pdb] PDB written: {pdb_path} ({len(pdb_bytes):,} bytes, {len(syms)} symbols)")

if __name__ == "__main__":
    main()
