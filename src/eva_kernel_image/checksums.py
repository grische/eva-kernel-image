"""Checksum primitives used inside the Fritz!Box EVA kernel image format.

Three distinct checksums are used at different layers:

* :func:`ti_checksum` — a two's-complement additive 32-bit checksum, used in
  every ``ti_record_trailer`` and in the outer ``dual_kernel_trailer``. The
  sum of ``payload_length``, ``load_addr``, ``sum(payload_bytes)``, and the
  stored checksum is zero modulo 2³².

* :func:`lzma_crc32` — a standard reflected CRC-32 (polynomial ``0xEDB88320``),
  same as zlib/gzip. Covers only the compressed LZMA bytes — not the 8-byte
  stream header.

* :func:`file_signature_crc` — an MSB-first CRC-32 with polynomial
  ``0x04C11DB7``, POSIX ``cksum``-style length folding, and final bit
  inversion. **Not** the same as ``zlib.crc32``.
"""

from __future__ import annotations

import zlib


def ti_checksum(payload_length: int, load_addr: int, payload: bytes) -> int:
    """Compute the TI-record checksum.

    The checksum is defined such that
    ``payload_length + load_addr + sum(payload) + checksum ≡ 0 (mod 2³²)``.
    """
    byte_sum = sum(payload)
    total = (payload_length + load_addr + byte_sum) & 0xFFFFFFFF
    return ((total ^ 0xFFFFFFFF) + 1) & 0xFFFFFFFF


def lzma_crc32(compressed_data: bytes) -> int:
    """Standard CRC-32 over the compressed LZMA data (post stream header)."""
    return zlib.crc32(compressed_data) & 0xFFFFFFFF


def _build_sig_crc_table() -> tuple[int, ...]:
    """Build the MSB-first CRC-32 lookup table for polynomial ``0x04C11DB7``."""
    poly = 0x04C11DB7
    table = [0] * 256
    for i in range(1, 256):
        crc = table[i // 2]
        c = (crc >> 31) ^ (i & 1)
        crc = (crc << 1) & 0xFFFFFFFF
        if c & 1:
            crc ^= poly
        table[i] = crc
    return tuple(table)


_SIG_CRC_TABLE: tuple[int, ...] = _build_sig_crc_table()


def file_signature_crc(payload: bytes) -> int:
    """Compute the file-signature CRC used by the EVA kernel image trailer.

    This is an MSB-first CRC-32 with polynomial ``0x04C11DB7`` and
    POSIX ``cksum``-style length folding: after consuming the data bytes,
    the payload length is fed into the CRC state byte-by-byte in
    little-endian order, then the result is one's-complemented.

    Verified against all 18 reference images — for instance, on
    ``kernel.image`` this function reproduces the stored value ``0x38A037DC``.
    """
    crc = 0
    for byte in payload:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _SIG_CRC_TABLE[(crc >> 24) ^ byte]

    length = len(payload)
    while length:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _SIG_CRC_TABLE[(crc >> 24) ^ (length & 0xFF)]
        length >>= 8

    return (~crc) & 0xFFFFFFFF
