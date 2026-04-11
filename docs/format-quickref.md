# Fritz!Box EVA Kernel Image — Quick Reference

Little-endian, packed, 4-byte aligned. Variant is determined by the first
4 bytes: `FEED9112` = dual-kernel, `FEED1281` = single-kernel. Every image
ends with an 8-byte file signature whose CRC covers all preceding bytes.

## Layout

    Single-kernel                       Dual-kernel
    +--------------------------+        +----------------------------------+
    | ti_record_header    (12) |        | dual_kernel_header          (12) |
    |   FEED1281               |        |   FEED9112  dpay_len  load_addr  |
    |   pay_len   load_addr    |        +----------------------------------+
    +--------------------------+        | 1st ti_record_header        (12) |
    | eva_lzma_header     (16) |        |   FEED1281  pay_len  load_addr   |
    |   075A0201               |        +----------------------------------+
    |   clen  ulen  data_crc32 |        | eva_lzma_header             (16) |
    +--------------------------+        |   075A0201  clen  ulen  data_crc |
    | lzma_stream_header   (8) |        +----------------------------------+
    |   props(1) dict_size(4)  |        | lzma_stream_header           (8) |
    |   00 00 00               |        |   props(1) dict_size(4) 00 00 00 |
    +--------------------------+        +----------------------------------+
    | compressed LZMA data     |        | compressed LZMA data      (clen) |
    |                   (clen) |        +----------------------------------+
    +--------------------------+        | 1st ti_record_trailer       (12) |
    | ti_record_trailer   (12) |        |   ti_crc  00000000   entry_addr  |
    |   ti_crc  00000000       |        +----------------------------------+
    |   entry_addr             |        | inter-record zero pad     (0..3) |
    +--------------------------+        +----------------------------------+
    | file_signature       (8) |        | 2nd ti_record_header        (12) |
    |   C453DE23  file_crc     |        |   FEEDB007  pay_len  load_addr   |
    +--------------------------+        | eva_lzma_header             (16) |
                                        | lzma_stream_header           (8) |
                                        | compressed LZMA data      (clen) |
                                        | 2nd ti_record_trailer       (12) |
                                        +----------------------------------+
                                        | dual trailing bytes     (var, 0) |  legacy only
                                        +----------------------------------+
                                        | dual_kernel_trailer         (12) |
                                        |   dual_crc 00000000 entry_addr   |
                                        +----------------------------------+
                                        | post-trailer zero padding  (var) |
                                        +----------------------------------+
                                        | file_signature               (8) |
                                        |   C453DE23  file_crc             |
                                        +----------------------------------+

- `pay_len` in `ti_record_header` = `clen + 24` (= 16 eva_lzma_header + 8 stream header + clen).
- `dpay_len` in `dual_kernel_header` spans everything from the byte after
  that header up to (not including) `dual_kernel_trailer`.
- `dual_kernel_trailer.entry_addr` = 1st TI record's `entry_addr`.
- `dual_kernel_header.load_addr` = 1st TI record's `load_addr`.

## Three checksums

**TI record** (`ti_record_trailer.crc`, `dual_kernel_trailer.crc`) —
two's-complement additive, so the sum is zero mod 2³²:

    pay_len + load_addr + sum(payload_bytes) + checksum ≡ 0 (mod 2³²)

**LZMA data** (`eva_lzma_header.data_crc32`) — standard reflected CRC-32
(polynomial `0xEDB88320`), same as zlib/gzip. Computed over the compressed
LZMA data only; does **not** include the 8-byte stream header.

**File signature** (`file_signature.crc`) — MSB-first CRC-32, polynomial
`0x04C11DB7`, with POSIX `cksum`-style length folding and final bit
inversion. **Not** the same as `zlib.crc32`. Covers bytes `[0, len-8)`.

    tbl = cksum_table(0x04C11DB7, msb_first)
    crc = 0
    for b in data:   crc = ((crc<<8) ^ tbl[(crc>>24)^b])          & 0xFFFFFFFF
    n = len(data)
    while n:         crc = ((crc<<8) ^ tbl[(crc>>24)^(n&0xFF)])   & 0xFFFFFFFF; n >>= 8
    return ~crc & 0xFFFFFFFF

## LZMA stream quirk

The EVA stream is standard LZMA-alone with the 8-byte uncompressed-size
field moved out of the stream and into `eva_lzma_header.ulen`. The 3 bytes
remaining in the stream position are zero-filled:

    EVA:      [props(1)] [dict_size(4)] [00 00 00]    [data]
    Standard: [props(1)] [dict_size(4)] [ulen(8 LE)]  [data]

To decode: synthesize a standard header using `props` and `dict_size` from
the stream header and `ulen` (4 bytes) from `eva_lzma_header`, append 4
zero bytes, then the compressed data. Feed to any LZMA1 decoder.

Observed everywhere: `props=0x5D` (lc=3, lp=0, pb=2), `dict_size=0x00800000`
(8 MiB).

## Magic values

| u32 (LE)    | Location                             |
|-------------|--------------------------------------|
| `FEED9112`  | `dual_kernel_header.magic`           |
| `FEED1281`  | `ti_record_header.magic` (primary)   |
| `FEEDB007`  | `ti_record_header.magic` (secondary) |
| `075A0201`  | `eva_lzma_header.type`               |
| `C453DE23`  | `file_signature.magic`               |
