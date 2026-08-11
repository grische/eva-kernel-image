# Fritz!Box EVA Kernel Image Format

| Field             | Value                                          |
|-------------------|------------------------------------------------|
| Version           | 1.0 (Draft, 2026-04-11)                        |
| Common extension  | `.image`                                       |
| Endianness        | Little-endian                                  |
| Alignment         | 4 bytes                                        |

This document specifies the binary format used by the AVM Fritz!Box EVA
bootloader to load LZMA-compressed Linux kernels. It is derived from
reverse engineering of 18 reference images covering the Fritz!Box 7530,
7560, 7580, 7583, 7590, and 7590 AX product lines across firmware
versions 06.92 through 08.10.

A reference parser, builder, and checksum implementation is provided in
`eva_converter.py`.

## Contents

1. [Overview](#1-overview)
2. [Conventions](#2-conventions)
3. [File Layout](#3-file-layout)
4. [Structures](#4-structures)
5. [Checksums](#5-checksums)
6. [LZMA Stream](#6-lzma-stream)
7. [Parsing and Generation Rules](#7-parsing-and-generation-rules)
8. [Worked Example](#8-worked-example)
9. [Security Considerations](#9-security-considerations)
10. [Magic Values](#10-magic-values)
11. [Open Questions](#11-open-questions)

---

## 1. Overview

Two variants of the format exist:

- **Single-kernel** — one TI record carrying one LZMA-compressed kernel.
  Observed on the Fritz!Box 7530 and 7583.
- **Dual-kernel** — a wrapper around two TI records. The second record
  carries coprocessor firmware. Observed on the Fritz!Box 7560, 7580,
  and 7590 product lines, which pair the main CPU with a DSL/Wi-Fi
  coprocessor on the Lantiq VR9 / Intel GRX5 SoC family.

The variant is determined by the first four bytes of the file:

```
0xFEED9112 → dual-kernel
0xFEED1281 → single-kernel
```

Every image ends with an 8-byte file signature (magic `0xC453DE23` plus
a 4-byte CRC covering everything before it).

## 2. Conventions

- All integers are unsigned and little-endian.
- Sizes are in bytes. Offsets are from the start of the file.
- Structures are packed; there is no implicit padding between fields.
- The key words "MUST", "SHOULD", and "MAY" are used in their RFC 2119
  sense.

## 3. File Layout

### 3.1 Single-kernel

```
offset  size          content
------  ------------  --------------------------------------
0x0000  12            ti_record_header    (magic FEED1281)
0x000C  16            eva_lzma_header     (type 075A0201)
0x001C  variable      eva_lzma_stream
...     12            ti_record_trailer
...     8             file_signature      (magic C453DE23)
```

### 3.2 Dual-kernel

```
offset  size          content
------  ------------  --------------------------------------
0x0000  12            dual_kernel_header  (magic FEED9112)
0x000C  12            ti_record_header    (magic FEED1281)  ─┐
        16            eva_lzma_header                        │
        variable      eva_lzma_stream                        │  1st TI
        12            ti_record_trailer                     ─┘  record
        0..3          inter-record padding (zero, to align 4B)
        12            ti_record_header    (magic FEEDB007)  ─┐
        16            eva_lzma_header                        │
        variable      eva_lzma_stream                        │  2nd TI
        12            ti_record_trailer                     ─┘  record
        variable      dual trailing bytes  (see §4.7)
        12            dual_kernel_trailer
        variable      post-trailer padding (zero)
        8             file_signature      (magic C453DE23)
```

## 4. Structures

All multi-byte fields are little-endian. Sizes are exact.

### 4.1 `dual_kernel_header` — dual-kernel only, 12 bytes

```c
struct dual_kernel_header {
    u32 magic;            // 0xFEED9112
    u32 payload_length;   // wrapped content length, see below
    u32 load_addr;        // matches the 1st TI record's load_addr
};
```

`payload_length` spans from the byte following this header up to (but
not including) the `dual_kernel_trailer`. It covers both TI records,
any inter-record padding, and the dual trailing bytes region.

### 4.2 `ti_record_header` — 12 bytes

```c
struct ti_record_header {
    u32 magic;            // 0xFEED1281 (primary) or 0xFEEDB007 (secondary)
    u32 payload_length;   // payload size in bytes (does not include trailer)
    u32 load_addr;        // physical memory load address
};
```

### 4.3 `ti_record_trailer` — 12 bytes

```c
struct ti_record_trailer {
    u32 checksum;         // additive checksum, see §5.1
    u32 zero;             // always 0x00000000
    u32 entry_addr;       // execution entry point
};
```

The `dual_kernel_trailer` in dual-kernel images uses the same layout.
Its `entry_addr` matches the primary TI record's `entry_addr`.

### 4.4 `eva_lzma_header` — 16 bytes

```c
struct eva_lzma_header {
    u32 type;             // 0x075A0201
    u32 compressed_len;   // LZMA data length (excludes the 8-byte stream header)
    u32 uncompressed_len; // size of decompressed kernel
    u32 data_checksum;    // zlib CRC-32 of the compressed data, see §5.2
};
```

Relation to the TI record header:
```
ti_record_header.payload_length = compressed_len + 24
                                = 16 (eva_lzma_header)
                                +  8 (eva_lzma_stream header)
                                +  compressed_len
```

### 4.5 `eva_lzma_stream` — variable length

```c
struct eva_lzma_stream {
    u8  properties;       // LZMA properties byte (always 0x5D)
    u32 dict_size;        // LZMA dictionary size (always 0x00800000 = 8 MiB)
    u8  reserved[3];      // always 0x00 0x00 0x00
    u8  data[/* compressed_len */];
};
```

The 3 reserved bytes align the compressed data to an 8-byte boundary
from the start of the stream header. Their content is always zero and
is not consumed during decompression.

### 4.6 Inter-record padding (dual-kernel only)

Zero, 1, 2, or 3 zero bytes inserted after the 1st TI record's trailer
so that the 2nd TI record header starts on a 4-byte-aligned file offset.

### 4.7 Dual trailing bytes (dual-kernel only)

In current images this region is empty. In older images (7560 v7.00,
v7.01, v7.12; 7580 v6.92) it contains zero padding followed by an extra
embedded `file_signature`. See §11.1. Parsers MUST preserve these bytes
verbatim; the outer dual-kernel checksum covers them.

### 4.8 `file_signature` — last 8 bytes of the file

```c
struct file_signature {
    u32 magic;            // 0xC453DE23
    u32 crc;              // see §5.3
};
```

The CRC covers every byte of the file before the signature.

## 5. Checksums

The format uses three different checksum algorithms. All three MUST be
valid for a conforming file.

### 5.1 TI record additive checksum

Used by `ti_record_trailer.checksum` (both TI records) and by the
`dual_kernel_trailer.checksum`.

The checksum is chosen so that, over 32-bit unsigned arithmetic:

```
payload_length + load_addr + Σ payload_bytes + checksum ≡ 0 (mod 2³²)
```

Equivalently:

```python
def ti_checksum(payload_length, load_addr, payload):
    s = (payload_length + load_addr + sum(payload)) & 0xFFFFFFFF
    return ((s ^ 0xFFFFFFFF) + 1) & 0xFFFFFFFF
```

For the dual-kernel trailer, `payload_length` and `load_addr` come from
the `dual_kernel_header` and the payload is the region described in §4.1.

### 5.2 LZMA data checksum

Used by `eva_lzma_header.data_checksum`.

Standard reflected CRC-32 (polynomial `0xEDB88320`, initial value
`0xFFFFFFFF`, final XOR `0xFFFFFFFF`) — the same algorithm as zlib and
gzip.

Input: exactly the `compressed_len` bytes of `eva_lzma_stream.data`.
The 8-byte stream header is not included.

```python
def lzma_data_checksum(data):
    return zlib.crc32(data) & 0xFFFFFFFF
```

### 5.3 File signature CRC

Used by `file_signature.crc`.

This is an **MSB-first** CRC-32 with polynomial `0x04C11DB7`, followed
by a length-folding step (as in POSIX `cksum`) and a final
bit-inversion. It is **not** the same as the reflected CRC-32 in §5.2;
`zlib.crc32` will not produce the correct value.

Input: all bytes of the file before the signature, i.e., the range
`[0, file_size − 8)`.

```python
def build_table():
    poly = 0x04C11DB7
    table = [0] * 256
    for i in range(1, 256):
        crc = table[i // 2]
        c = (crc >> 31) ^ (i & 1)
        crc = (crc << 1) & 0xFFFFFFFF
        if c & 1:
            crc ^= poly
        table[i] = crc
    return table


def file_signature_crc(payload):
    table = build_table()
    crc = 0
    for b in payload:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ table[(crc >> 24) ^ b]
    length = len(payload)
    while length:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ table[(crc >> 24) ^ (length & 0xFF)]
        length >>= 8
    return (~crc) & 0xFFFFFFFF
```

## 6. LZMA Stream

The EVA LZMA stream is a small variation of the standard LZMA "alone"
format. The uncompressed size is moved out of the stream header into
`eva_lzma_header.uncompressed_len`; the three bytes freed inside the
stream are kept as zero padding.

### 6.1 Decoding: EVA → standard LZMA-alone

Build a synthetic standard LZMA-alone header:

```
properties        (1 byte,  from eva_lzma_stream)
dict_size         (4 bytes, from eva_lzma_stream)
uncompressed_len  (4 bytes, from eva_lzma_header)
0x00 0x00 0x00 0x00  (4 bytes of zero, upper half of the 64-bit size field)
```

Concatenate with `eva_lzma_stream.data` and feed to any standard LZMA1
decoder (e.g., Python's `lzma.decompress(..., format=lzma.FORMAT_ALONE)`).

### 6.2 Encoding: standard LZMA-alone → EVA

Reverse the process: extract `properties`, `dict_size`,
`uncompressed_len`, and the compressed data from a standard stream,
then write:

```
properties (1) + dict_size (4) + 0x00 0x00 0x00 (3) + compressed_data
```

Store `uncompressed_len` in `eva_lzma_header.uncompressed_len` and the
compressed data length in `compressed_len`. Compute `data_checksum`
(§5.2) over the compressed data.

### 6.3 Compression parameters

All observed images use the same parameters:

| Parameter       | Value      |
|-----------------|------------|
| properties byte | `0x5D`     |
| lc / lp / pb    | 3 / 0 / 2  |
| dictionary size | 8 MiB      |

## 7. Parsing and Generation Rules

A parser MUST:

1. Dispatch on the first 4 bytes (`0xFEED9112` → dual, `0xFEED1281` →
   single; anything else → reject).
2. Validate every magic value it encounters (`FEED1281`, `FEEDB007`,
   `075A0201`, `C453DE23`).
3. Verify that `ti_record_trailer.zero` is `0x00000000`.
4. Verify all three checksums (§5). Mismatches MAY be reported as
   warnings rather than fatal errors for forensic use cases.
5. Bounds-check every length field against the remaining file size
   before reading.
6. Preserve the inter-record padding (§4.6), dual trailing bytes
   (§4.7), and post-trailer padding verbatim if byte-identical
   round-trip output is required. LZMA compression is not
   deterministic across encoders, so round-trip fidelity also requires
   preserving the original compressed bytes.

A generator MUST:

1. Emit all integers little-endian.
2. Insert 0–3 zero bytes of inter-record padding so that the 2nd TI
   record header is 4-byte-aligned.
3. Set `ti_record_trailer.zero` to zero and the 3 reserved LZMA bytes
   to zero.
4. Compute all three checksums.
5. Keep the length fields consistent
   (`ti_record_header.payload_length = compressed_len + 24`,
   `dual_kernel_header.payload_length` as in §4.1).
6. For dual-kernel images, mirror the 1st TI record's `load_addr` in
   the `dual_kernel_header` and its `entry_addr` in the
   `dual_kernel_trailer`.

## 8. Worked Example

The extracted `kernel.image` from FRITZ.Box_7560-07.28.image
(size 6,295,048 bytes, dual-kernel).

**First 48 bytes (hex):**

```
00000000  12 91 ed fe 18 0d 60 00  00 00 50 80 81 12 ed fe
00000010  fe 85 32 00 00 00 50 80  01 02 5a 07 e6 85 32 00
00000020  03 78 b4 00 8a fb 38 02  5d 00 00 80 00 00 00 00
```

**Decoded:**

```
dual_kernel_header @ 0x000000
  magic          = 0xFEED9112
  payload_length = 0x00600D18   (6,294,808)
  load_addr      = 0x80500000

1st ti_record_header @ 0x00000C
  magic          = 0xFEED1281
  payload_length = 0x003285FE   (3,310,078)
  load_addr      = 0x80500000

eva_lzma_header @ 0x000018
  type             = 0x075A0201
  compressed_len   = 0x003285E6
  uncompressed_len = 0x00B47803
  data_checksum    = 0x0238FB8A

eva_lzma_stream header @ 0x000028
  properties = 0x5D  dict_size = 0x00800000  reserved = 00 00 00
  (compressed data starts at 0x000030)

1st ti_record_trailer @ 0x328616
  checksum 0x5B271077, zero 0x00000000, entry_addr 0x80C8B500

inter-record padding @ 0x328622..0x328623  (2 zero bytes)

2nd ti_record_header @ 0x328624
  magic          = 0xFEEDB007
  payload_length = 0x002D8607
  load_addr      = 0x8DFFFFFC

eva_lzma_header @ 0x328630
  type             = 0x075A0201
  compressed_len   = 0x002D85EF
  uncompressed_len = 0x007D72B9
  data_checksum    = 0x4593F930

2nd ti_record_trailer @ 0x600C37
  checksum 0x5B271077, zero 0x00000000, entry_addr 0x8E691770

dual_kernel_trailer @ 0x600D24
  checksum 0x4F79D764, zero 0x00000000, entry_addr 0x80C8B500

file_signature @ 0x600E00
  magic = 0xC453DE23, crc = 0x38A037DC
```

## 9. Security Considerations

- **CRCs are error-detecting only.** None of the three checksums
  provides cryptographic integrity. A file whose checksums validate has
  only been shown to be free of accidental corruption; it has not been
  authenticated.
- **Trust length fields cautiously.** A parser that follows
  `payload_length` or `compressed_len` without cross-checking against
  the remaining file size is vulnerable to buffer over-read.
- **Decompression bombs.** `uncompressed_len` can be much larger than
  `compressed_len`. Cap allocation at a sensible limit (e.g., 64 MiB
  for typical Fritz!Box kernels).
- **32-bit arithmetic.** The TI checksum relies on mod-2³² wraparound;
  parsers written in languages with unbounded integers must mask
  intermediates to 32 bits.

## 10. Magic Values

| Name             | Value (LE u32) | Raw bytes         |
|------------------|----------------|-------------------|
| `DUAL_KERNEL`    | `0xFEED9112`   | `12 91 ed fe`     |
| `TI_AR7`         | `0xFEED1281`   | `81 12 ed fe`     |
| `TI_AR7_2ND`     | `0xFEEDB007`   | `07 b0 ed fe`     |
| `TI_PUMA6`       | `0xFEED8112`   | `12 81 ed fe`     |
| `EVA_LZMA_TYPE`  | `0x075A0201`   | `01 02 5a 07`     |
| `FILE_SIGNATURE` | `0xC453DE23`   | `23 de 53 c4`     |

## 11. Open Questions

### 11.1 Legacy embedded signature

The dual trailing bytes region (§4.7) in older images (7560 v7.00,
v7.01, v7.12; 7580 v6.92) contains an extra 8-byte structure matching
the `file_signature` layout. The outer `dual_kernel_trailer` checksum
covers these bytes, so they must be preserved verbatim, but the exact
payload range the inner signature's CRC was computed over has not
been reverse engineered. The working hypothesis is that these older
firmwares pre-date the dual-kernel wrapper and retain an inner
signature from the earlier format.

### 11.2 Secondary load address `0x8DFFFFFC`

All observed dual-kernel images have `0x8DFFFFFC` in the secondary TI
record's `load_addr`. This is not a natural MIPS KSEG0 memory address
and is likely a bootloader-specific convention for the VR9/GRX5
coprocessor firmware. Its precise meaning has not been confirmed.
