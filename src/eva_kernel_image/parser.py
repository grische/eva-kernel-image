"""Parser for the Fritz!Box EVA kernel image format.

This module is strict about structural correctness — wrong magic values,
truncated records, or inconsistent length fields raise :class:`ParseError`
— but does **not** validate checksums. Checksum validation is a separate,
explicit call: either :func:`eva_kernel_image.validator.validate_image` or the
:meth:`EVAImage.validate` method. This separation lets research workflows
inspect partially-corrupted images without having the parser refuse them.
"""

from __future__ import annotations

import struct

from eva_kernel_image.constants import (
    DUAL_KERNEL_MAGIC,
    EVA_LZMA_HEADER_SIZE,
    EVA_LZMA_STREAM_HEADER_SIZE,
    EVA_LZMA_TYPE,
    FILE_SIGNATURE_SIZE,
    SIGNATURE_MAGIC,
    TI_AR7_2ND_MAGIC,
    TI_AR7_MAGIC,
    TI_HEADER_SIZE,
    TI_TRAILER_SIZE,
)
from eva_kernel_image.exceptions import ParseError
from eva_kernel_image.lzma_codec import EVALzmaPayload
from eva_kernel_image.model import (
    DualHeader,
    EVAImage,
    FileSignature,
    LegacyPadding,
    TIRecord,
)


def _read_u32_le(data: bytes, offset: int) -> int:
    value: int = struct.unpack_from("<I", data, offset)[0]
    return value


def _parse_lzma_payload(payload: bytes) -> EVALzmaPayload:
    """Parse the LZMA payload embedded inside a TI record's payload bytes."""
    if len(payload) < EVA_LZMA_HEADER_SIZE + EVA_LZMA_STREAM_HEADER_SIZE:
        raise ParseError(f"payload too short for LZMA header: {len(payload)} bytes")

    type_magic, compressed_len, uncompressed_len, data_checksum = struct.unpack_from(
        "<IIII",
        payload,
        0,
    )
    if type_magic != EVA_LZMA_TYPE:
        raise ParseError(f"expected LZMA type magic 0x{EVA_LZMA_TYPE:08X}, got 0x{type_magic:08X}")

    stream_off = EVA_LZMA_HEADER_SIZE
    properties = payload[stream_off]
    dict_size = _read_u32_le(payload, stream_off + 1)
    stream_header_padding = payload[stream_off + 5 : stream_off + 8]

    data_off = stream_off + EVA_LZMA_STREAM_HEADER_SIZE
    if len(payload) < data_off + compressed_len:
        raise ParseError(
            f"payload shorter than declared compressed_len: "
            f"got {len(payload)} bytes, need {data_off + compressed_len}",
        )
    compressed_data = payload[data_off : data_off + compressed_len]

    return EVALzmaPayload(
        compressed_len=compressed_len,
        uncompressed_len=uncompressed_len,
        data_checksum=data_checksum,
        properties=properties,
        dict_size=dict_size,
        stream_header_padding=stream_header_padding,
        compressed_data=compressed_data,
    )


def _parse_ti_record(data: bytes, offset: int, expected_magic: int) -> TIRecord:
    """Parse one TI record at the given file offset."""
    if len(data) < offset + TI_HEADER_SIZE:
        raise ParseError(f"truncated TI record header at offset 0x{offset:X}")

    magic, payload_length, load_addr = struct.unpack_from("<III", data, offset)
    if magic != expected_magic:
        raise ParseError(
            f"expected TI magic 0x{expected_magic:08X} at offset 0x{offset:X}, got 0x{magic:08X}",
        )

    payload_start = offset + TI_HEADER_SIZE
    payload_end = payload_start + payload_length
    trailer_end = payload_end + TI_TRAILER_SIZE
    if len(data) < trailer_end:
        raise ParseError(
            f"truncated TI record at offset 0x{offset:X}: "
            f"need {trailer_end} bytes, have {len(data)}",
        )

    raw_payload = data[payload_start:payload_end]
    lzma_payload = _parse_lzma_payload(raw_payload)

    checksum, zero, entry_addr = struct.unpack_from("<III", data, payload_end)
    if zero != 0:
        raise ParseError(
            f"expected zero word in TI trailer at offset 0x{payload_end + 4:X}, got 0x{zero:08X}",
        )

    return TIRecord(
        magic=magic,
        load_addr=load_addr,
        entry_addr=entry_addr,
        checksum=checksum,
        lzma=lzma_payload,
    )


def parse_image(data: bytes) -> EVAImage:
    """Parse a Fritz!Box EVA kernel image (single- or dual-kernel variant).

    Performs structural validation only — magic numbers, length fields,
    padding regions. Checksum mismatches are not raised as ``ParseError``;
    call :meth:`EVAImage.validate` on the returned image to check those.
    """
    if len(data) < TI_HEADER_SIZE + TI_TRAILER_SIZE + FILE_SIGNATURE_SIZE:
        raise ParseError(f"image too short: {len(data)} bytes")

    first_magic = _read_u32_le(data, 0)
    if first_magic == DUAL_KERNEL_MAGIC:
        return _parse_dual_kernel_image(data)
    if first_magic == TI_AR7_MAGIC:
        return _parse_single_kernel_image(data)
    raise ParseError(
        f"unknown magic at offset 0: 0x{first_magic:08X} "
        f"(expected 0x{DUAL_KERNEL_MAGIC:08X} or 0x{TI_AR7_MAGIC:08X})",
    )


def _parse_dual_kernel_image(data: bytes) -> EVAImage:
    """Parse a dual-kernel image (``0xFEED9112`` wrapper around two TI records)."""
    _magic, dual_payload_length, dual_load_addr = struct.unpack_from("<III", data, 0)

    # Primary TI record follows the dual header.
    primary = _parse_ti_record(data, TI_HEADER_SIZE, TI_AR7_MAGIC)
    after_primary = TI_HEADER_SIZE + TI_HEADER_SIZE + primary.payload_length + TI_TRAILER_SIZE

    # Inter-record alignment padding to a 4-byte boundary.
    aligned = (after_primary + 3) & ~3
    inter_record_padding = data[after_primary:aligned]

    # Secondary TI record.
    secondary = _parse_ti_record(data, aligned, TI_AR7_2ND_MAGIC)
    after_secondary = aligned + TI_HEADER_SIZE + secondary.payload_length + TI_TRAILER_SIZE

    # Dual trailer sits at offset TI_HEADER_SIZE + dual_payload_length. Older
    # images embed extra bytes (zeros + an inner file-signature) between the
    # end of the secondary TI record and the dual trailer; preserve them.
    dual_trailer_start = TI_HEADER_SIZE + dual_payload_length
    if len(data) < dual_trailer_start + TI_TRAILER_SIZE:
        raise ParseError(
            f"dual kernel trailer extends past EOF: need "
            f"{dual_trailer_start + TI_TRAILER_SIZE} bytes",
        )
    if dual_trailer_start < after_secondary:
        raise ParseError(
            f"dual_payload_length ({dual_payload_length}) ends before the secondary "
            f"TI record (at offset 0x{after_secondary:X})",
        )
    dual_trailing_bytes = data[after_secondary:dual_trailer_start]

    dual_checksum, dual_zero, dual_entry_addr = struct.unpack_from("<III", data, dual_trailer_start)
    if dual_zero != 0:
        raise ParseError(
            f"expected zero word in dual trailer at offset 0x{dual_trailer_start + 4:X}, "
            f"got 0x{dual_zero:08X}",
        )

    # Post-data padding between the dual trailer and the trailing file signature.
    post_data_start = dual_trailer_start + TI_TRAILER_SIZE
    signature_start = len(data) - FILE_SIGNATURE_SIZE
    if signature_start < post_data_start:
        raise ParseError("file signature overlaps dual trailer region")
    post_data_padding = data[post_data_start:signature_start]

    # Trailing file signature.
    sig_magic, signature_crc = struct.unpack_from("<II", data, signature_start)
    if sig_magic != SIGNATURE_MAGIC:
        raise ParseError(
            f"expected signature magic 0x{SIGNATURE_MAGIC:08X} at end, got 0x{sig_magic:08X}",
        )

    return EVAImage(
        records=[primary, secondary],
        dual_header=DualHeader(
            payload_length=dual_payload_length,
            load_addr=dual_load_addr,
            entry_addr=dual_entry_addr,
            checksum=dual_checksum,
        ),
        signature=FileSignature(crc=signature_crc),
        legacy_padding=LegacyPadding(
            inter_record=inter_record_padding,
            dual_trailing=dual_trailing_bytes,
            post_data=post_data_padding,
        ),
    )


def _parse_single_kernel_image(data: bytes) -> EVAImage:
    """Parse a single-kernel image (no dual wrapper)."""
    primary = _parse_ti_record(data, 0, TI_AR7_MAGIC)
    after_primary = TI_HEADER_SIZE + primary.payload_length + TI_TRAILER_SIZE

    # Single-kernel images may or may not carry a trailing file signature.
    signature: FileSignature | None = None
    post_data_padding = b""
    if len(data) >= after_primary + FILE_SIGNATURE_SIZE:
        trailing_magic = _read_u32_le(data, len(data) - FILE_SIGNATURE_SIZE)
        if trailing_magic == SIGNATURE_MAGIC:
            signature_crc = _read_u32_le(data, len(data) - 4)
            signature = FileSignature(crc=signature_crc)
            post_data_padding = data[after_primary : len(data) - FILE_SIGNATURE_SIZE]

    return EVAImage(
        records=[primary],
        dual_header=None,
        signature=signature,
        legacy_padding=LegacyPadding(post_data=post_data_padding),
    )
