"""Serialiser: turn an :class:`EVAImage` back into its on-disk bytes.

For images parsed from an AVM-shipped file and then rebuilt unchanged, the
output is byte-identical to the input. This is asserted as a round-trip
invariant in the tests and as the spot-check acceptance criterion against
the reference corpus.
"""

from __future__ import annotations

import struct

from eva_kernel_image.checksums import file_signature_crc, ti_checksum
from eva_kernel_image.constants import (
    DUAL_KERNEL_MAGIC,
    EVA_LZMA_TYPE,
    SIGNATURE_MAGIC,
)
from eva_kernel_image.exceptions import BuildError
from eva_kernel_image.lzma_codec import EVALzmaPayload
from eva_kernel_image.model import EVAImage, TIRecord


def build_lzma_payload(lzma: EVALzmaPayload) -> bytes:
    """Serialise an :class:`EVALzmaPayload` into its on-disk bytes.

    Layout (little-endian): 16-byte ``eva_lzma_header`` (type magic, compressed
    length, uncompressed length, data CRC) followed by 8-byte
    ``eva_lzma_stream_header`` (properties, dict_size, 3 reserved bytes) and
    the ``compressed_data`` bytes.
    """
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


def build_ti_record(record: TIRecord) -> bytes:
    """Serialise one TI record: header + payload + trailer.

    The stored ``record.checksum`` is ignored — the trailer checksum is
    always freshly computed from the payload. That means you can mutate
    ``record.lzma`` and rebuild without needing to update the checksum
    field by hand first.
    """
    payload = build_lzma_payload(record.lzma)
    payload_length = len(payload)
    header = struct.pack("<III", record.magic, payload_length, record.load_addr)
    checksum = ti_checksum(payload_length, record.load_addr, payload)
    trailer = struct.pack("<III", checksum, 0, record.entry_addr)
    return header + payload + trailer


def build_image(image: EVAImage) -> bytes:
    """Serialise a full :class:`EVAImage` into its on-disk bytes.

    Round-trip invariant: ``build_image(parse_image(data)) == data`` for any
    ``data`` that is a valid, structurally-consistent EVA kernel image.
    Checksums (TI records, dual trailer, file signature) are always freshly
    computed from the emitted content, not copied from the parsed values.
    """
    if not image.records:
        raise BuildError("EVAImage has no records")

    out = bytearray()

    if image.dual_header is not None:
        if len(image.records) != 2:
            raise BuildError(
                f"dual-kernel image must have exactly 2 records, got {len(image.records)}",
            )

        # Build the "dual payload": primary TI record + inter-record padding
        # + secondary TI record + any legacy trailing bytes.
        dual_payload = bytearray()
        dual_payload.extend(build_ti_record(image.records[0]))
        dual_payload.extend(image.legacy_padding.inter_record)
        dual_payload.extend(build_ti_record(image.records[1]))
        dual_payload.extend(image.legacy_padding.dual_trailing)

        # Cross-check: the dual_header's recorded payload length must match
        # what we just assembled, otherwise the image was modified in a way
        # that requires the caller to update dual_header.payload_length.
        if len(dual_payload) != image.dual_header.payload_length:
            raise BuildError(
                f"built dual payload length ({len(dual_payload)}) does not match "
                f"dual_header.payload_length ({image.dual_header.payload_length}); "
                f"update the field before rebuilding",
            )

        dual_header_bytes = struct.pack(
            "<III",
            DUAL_KERNEL_MAGIC,
            image.dual_header.payload_length,
            image.dual_header.load_addr,
        )
        dual_checksum = ti_checksum(
            image.dual_header.payload_length,
            image.dual_header.load_addr,
            bytes(dual_payload),
        )
        dual_trailer = struct.pack("<III", dual_checksum, 0, image.dual_header.entry_addr)
        out.extend(dual_header_bytes)
        out.extend(dual_payload)
        out.extend(dual_trailer)
    else:
        if len(image.records) != 1:
            raise BuildError(
                f"single-kernel image must have exactly 1 record, got {len(image.records)}",
            )
        out.extend(build_ti_record(image.records[0]))

    # Post-data padding between the last trailer and the file signature.
    out.extend(image.legacy_padding.post_data)

    # File signature (if the image had one on disk, or if it's dual-kernel —
    # every observed dual-kernel image carries a trailing signature).
    if image.signature is not None or image.dual_header is not None:
        sig_crc = file_signature_crc(bytes(out))
        out.extend(struct.pack("<II", SIGNATURE_MAGIC, sig_crc))

    return bytes(out)
