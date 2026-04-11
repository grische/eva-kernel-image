"""LZMA1 codec for the Fritz!Box EVA kernel image format.

The EVA format wraps an LZMA1 payload in a custom 16-byte header plus an
8-byte stream header. The two differ from a standard ``.lzma`` (alone-format)
stream in two small ways:

1. The 8-byte uncompressed-size field normally found after ``dict_size`` in
   an alone-format header is moved out of the stream and stored separately
   in ``eva_lzma_header.ulen``. The three remaining bytes in the stream
   position are zero-filled.
2. A 16-byte ``eva_lzma_header`` precedes the stream. It carries the type
   magic (``0x075A0201``), compressed length, uncompressed length, and a
   CRC-32 over the compressed data.

Every reference image uses the same LZMA1 parameters: ``properties=0x5D``
(lc=3, lp=0, pb=2) with an 8 MiB dictionary.

This module contains the low-level encode/decode primitives and the
:class:`EVALzmaPayload` dataclass that glues them together.

Encoder notes
-------------
Python's stdlib ``lzma`` module produces alone-format streams via liblzma,
the same backend as the ``xz`` CLI. Both encoders emit an end-of-payload
marker (EOPM) at the end of the LZMA1 bitstream, which makes the stream
decode only when the external ``ulen`` is set to the "unknown" sentinel
``0xFFFFFFFFFFFFFFFF``. AVM-shipped streams, by contrast, carry no EOPM
and terminate exactly at ``ulen`` bytes of output.

The Fritz!Box urlader's LZMA1 decoder is lenient about either shape — both
AVM-produced and stdlib-produced streams boot on real hardware (verified
by RAM-booting a repacked kernel on a Fritz!Box 7560, 2026-04-11). The
library's own :func:`unpack_eva_lzma` function uses a two-path fallback so
both shapes round-trip inside Python as well.
"""

from __future__ import annotations

import lzma
import struct
from dataclasses import dataclass

from eva_kernel_image.checksums import lzma_crc32
from eva_kernel_image.constants import EVA_LZMA_DICT_SIZE
from eva_kernel_image.exceptions import LzmaCodecError

_ALONE_HEADER_SIZE = 13  # properties(1) + dict_size(4) + uncompressed_size(8)
_ULEN_UNKNOWN = 0xFFFFFFFFFFFFFFFF


@dataclass(slots=True)
class EVALzmaPayload:
    """Parsed (or newly built) LZMA payload inside a TI record.

    Field order matches the byte layout of ``eva_lzma_header`` followed by
    the 8-byte ``eva_lzma_stream_header`` and the compressed bytes.
    """

    compressed_len: int
    uncompressed_len: int
    data_checksum: int
    properties: int  # LZMA properties byte, always 0x5D in observed images
    dict_size: int  # LZMA dictionary size, always 0x00800000 in observed images
    stream_header_padding: bytes  # 3 bytes between dict_size and compressed data (zeros)
    compressed_data: bytes  # exactly compressed_len bytes


def pack_eva_lzma(raw_kernel: bytes) -> EVALzmaPayload:
    """Compress a raw kernel into an EVA LZMA payload using stdlib only.

    Uses ``lzma.LZMACompressor`` with ``FORMAT_ALONE`` and an explicit LZMA1
    filter chain matching the parameters observed in every reference image
    (``lc=3, lp=0, pb=2, dict=8 MiB`` → properties byte ``0x5D``).
    """
    filters: list[dict[str, int]] = [
        {
            "id": lzma.FILTER_LZMA1,
            "dict_size": EVA_LZMA_DICT_SIZE,
            "lc": 3,
            "lp": 0,
            "pb": 2,
        },
    ]
    try:
        compressor = lzma.LZMACompressor(format=lzma.FORMAT_ALONE, filters=filters)
        alone_stream = compressor.compress(raw_kernel) + compressor.flush()
    except lzma.LZMAError as exc:  # pragma: no cover - extremely unlikely
        raise LzmaCodecError(f"stdlib lzma encoder failed: {exc}") from exc

    if len(alone_stream) < _ALONE_HEADER_SIZE:
        raise LzmaCodecError(
            f"lzma encoder output too short: {len(alone_stream)} < {_ALONE_HEADER_SIZE}",
        )

    properties = alone_stream[0]
    dict_size = struct.unpack_from("<I", alone_stream, 1)[0]
    compressed_data = alone_stream[_ALONE_HEADER_SIZE:]

    return EVALzmaPayload(
        compressed_len=len(compressed_data),
        uncompressed_len=len(raw_kernel),
        data_checksum=lzma_crc32(compressed_data),
        properties=properties,
        dict_size=dict_size,
        stream_header_padding=b"\x00\x00\x00",
        compressed_data=compressed_data,
    )


def unpack_eva_lzma(payload: EVALzmaPayload) -> bytes:
    """Decompress an EVA LZMA payload back into the raw kernel bytes.

    Two-path fallback: we first reconstruct a standard alone-format header
    using the real ``uncompressed_len`` (which works on AVM-shipped streams
    that have no EOPM). If that raises — as it will for streams produced by
    xz or stdlib, because they contain an EOPM that upsets liblzma when a
    concrete ``ulen`` is specified — we retry with the "unknown size"
    sentinel, which makes liblzma scan for the EOPM and stop there.
    """
    dict_size_le = struct.pack("<I", payload.dict_size)

    # Path 1: real ulen (works on AVM streams, no EOPM)
    header_real = (
        bytes([payload.properties]) + dict_size_le + struct.pack("<Q", payload.uncompressed_len)
    )
    try:
        return lzma.decompress(header_real + payload.compressed_data, format=lzma.FORMAT_ALONE)
    except lzma.LZMAError:
        pass

    # Path 2: unknown ulen (works on stdlib/xz streams with EOPM)
    header_unknown = bytes([payload.properties]) + dict_size_le + struct.pack("<Q", _ULEN_UNKNOWN)
    try:
        return lzma.decompress(header_unknown + payload.compressed_data, format=lzma.FORMAT_ALONE)
    except lzma.LZMAError as exc:
        raise LzmaCodecError(
            f"failed to decompress EVA LZMA payload ({payload.compressed_len} bytes compressed, "
            f"{payload.uncompressed_len} bytes expected): {exc}",
        ) from exc
