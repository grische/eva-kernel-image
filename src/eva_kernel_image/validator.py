"""Checksum validator for parsed :class:`EVAImage` objects.

Returns a list of human-readable error strings rather than raising — the
parser is already strict about structural correctness, and this module is
meant to let callers choose how loudly to complain about checksum drift.
For images parsed from disk, the four checksum classes checked here are:

1. Every TI record's additive trailer checksum.
2. Every LZMA payload's CRC-32 over the compressed data.
3. The outer dual-kernel trailer's additive checksum (dual images only).
4. The trailing file signature's POSIX cksum-style CRC (when the raw bytes
   the image was parsed from are supplied).
"""

from __future__ import annotations

import struct

from eva_kernel_image.checksums import file_signature_crc, lzma_crc32, ti_checksum
from eva_kernel_image.constants import (
    FILE_SIGNATURE_SIZE,
    TI_HEADER_SIZE,
)
from eva_kernel_image.lzma_codec import EVALzmaPayload
from eva_kernel_image.model import EVAImage, TIRecord


def _check_ti_record(record: TIRecord, label: str) -> list[str]:
    errors: list[str] = []
    payload = _ti_payload_bytes(record.lzma)
    computed = ti_checksum(record.payload_length, record.load_addr, payload)
    if computed != record.checksum:
        errors.append(
            f"{label} TI checksum mismatch: "
            f"stored=0x{record.checksum:08X} calculated=0x{computed:08X}",
        )
    lzma_computed = lzma_crc32(record.lzma.compressed_data)
    if lzma_computed != record.lzma.data_checksum:
        errors.append(
            f"{label} LZMA data checksum mismatch: "
            f"stored=0x{record.lzma.data_checksum:08X} calculated=0x{lzma_computed:08X}",
        )
    return errors


def _ti_payload_bytes(lzma: EVALzmaPayload) -> bytes:
    """Re-serialise just the LZMA payload bytes, for checksum computation.

    Kept inline rather than importing from :mod:`eva_kernel_image.builder` to avoid
    a circular import (builder imports model, model wants validator).
    """
    from eva_kernel_image.constants import EVA_LZMA_TYPE

    header = struct.pack(
        "<IIII",
        EVA_LZMA_TYPE,
        lzma.compressed_len,
        lzma.uncompressed_len,
        lzma.data_checksum,
    )
    stream_header = (
        bytes([lzma.properties]) + struct.pack("<I", lzma.dict_size) + lzma.stream_header_padding
    )
    return header + stream_header + lzma.compressed_data


def validate_image(image: EVAImage, original_bytes: bytes | None = None) -> list[str]:
    """Return a list of checksum error messages, or ``[]`` if all clean.

    Pass the raw bytes the image was parsed from as ``original_bytes`` to
    enable the outer file-signature CRC check. If not supplied, that check
    is skipped (the signature covers exact on-disk bytes, which may differ
    from what :func:`build_image` would re-emit for the same logical image).
    """
    errors: list[str] = []

    errors.extend(_check_ti_record(image.primary, "primary"))
    if image.secondary is not None:
        errors.extend(_check_ti_record(image.secondary, "secondary"))

    if image.dual_header is not None and original_bytes is not None:
        # The dual-trailer checksum covers everything between the dual header
        # and the dual trailer — i.e. the dual_payload_length bytes starting
        # at offset TI_HEADER_SIZE.
        payload_start = TI_HEADER_SIZE
        payload_end = payload_start + image.dual_header.payload_length
        if len(original_bytes) < payload_end:
            errors.append("dual_payload_length exceeds file size")
        else:
            dual_payload = original_bytes[payload_start:payload_end]
            computed = ti_checksum(
                image.dual_header.payload_length,
                image.dual_header.load_addr,
                dual_payload,
            )
            if computed != image.dual_header.checksum:
                errors.append(
                    f"dual kernel checksum mismatch: "
                    f"stored=0x{image.dual_header.checksum:08X} "
                    f"calculated=0x{computed:08X}",
                )

    if image.signature is not None and original_bytes is not None:
        sig_covered = original_bytes[: len(original_bytes) - FILE_SIGNATURE_SIZE]
        computed = file_signature_crc(sig_covered)
        if computed != image.signature.crc:
            errors.append(
                f"file signature CRC mismatch: "
                f"stored=0x{image.signature.crc:08X} calculated=0x{computed:08X}",
            )

    return errors
