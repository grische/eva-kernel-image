"""Data model for a parsed (or newly built) Fritz!Box EVA kernel image.

The model mirrors the on-disk structure described in ``docs/format-spec.md``
but replaces the flat field layout of the original research script with a
small set of composed dataclasses:

* :class:`EVALzmaPayload` (defined in :mod:`eva_kernel_image.lzma_codec`) — one
  compressed kernel slot, including its EVA LZMA header and stream header.
* :class:`TIRecord` — one TI record (header + LZMA payload + trailer).
* :class:`DualHeader` — the outer dual-kernel wrapper fields. ``None`` for
  single-kernel images.
* :class:`FileSignature` — the trailing 8-byte file signature (``0xC453DE23``
  + CRC-32). ``None`` for older single-kernel images that don't carry one.
* :class:`LegacyPadding` — bytes that exist purely for round-trip fidelity
  with AVM-shipped images (alignment gaps, embedded inner signatures on a
  handful of older dual-kernel builds, trailing zero fill).
* :class:`EVAImage` — the top-level container, combining all of the above.

``EVAImage.primary`` and ``EVAImage.secondary`` are convenience properties
that index into ``records``. Callers who want to modify the image should
operate on the ``records`` list directly or use
:meth:`TIRecord.replace_kernel`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from eva_kernel_image.constants import (
    EVA_LZMA_HEADER_SIZE,
    EVA_LZMA_STREAM_HEADER_SIZE,
)
from eva_kernel_image.lzma_codec import EVALzmaPayload, pack_eva_lzma, unpack_eva_lzma


@dataclass(slots=True)
class DualHeader:
    """Outer wrapper around a dual-kernel image (magic ``0xFEED9112``).

    ``payload_length`` is the length of everything between the dual header
    and the dual trailer — i.e. both TI records plus any inter-record
    padding and legacy trailing bytes. ``checksum`` is the stored TI-style
    additive checksum, used for validation; the builder always recomputes
    it from the emitted bytes.
    """

    payload_length: int
    load_addr: int
    entry_addr: int
    checksum: int


@dataclass(slots=True)
class FileSignature:
    """Trailing 8-byte file signature (magic ``0xC453DE23`` + CRC-32)."""

    crc: int


@dataclass(slots=True)
class LegacyPadding:
    """Opaque byte regions preserved for byte-identical round-trip fidelity.

    Most callers can ignore these. They exist because a handful of older
    reference images carry non-zero bytes in regions the spec otherwise
    describes as zero padding. Keeping them verbatim lets :func:`build_image`
    reproduce those files byte-for-byte.
    """

    inter_record: bytes = b""
    dual_trailing: bytes = b""
    post_data: bytes = b""


@dataclass(slots=True)
class TIRecord:
    """Parsed TI record: header + LZMA payload + trailer.

    The LZMA payload is stored as an :class:`EVALzmaPayload`, not as raw
    bytes — that lets the builder reproduce the exact same wire bytes
    deterministically via :func:`eva_kernel_image.builder.build_lzma_payload`.
    Callers looking to swap in a new kernel should use
    :meth:`replace_kernel` rather than constructing a new ``EVALzmaPayload``
    by hand.
    """

    magic: int
    load_addr: int
    entry_addr: int
    checksum: int
    lzma: EVALzmaPayload

    @property
    def payload_length(self) -> int:
        """Number of bytes in the TI record's payload field (derived)."""
        return EVA_LZMA_HEADER_SIZE + EVA_LZMA_STREAM_HEADER_SIZE + self.lzma.compressed_len

    def decompress(self) -> bytes:
        """Return the raw (decompressed) kernel bytes for this TI record."""
        return unpack_eva_lzma(self.lzma)

    def replace_kernel(self, raw: bytes) -> None:
        """Replace the compressed payload with a fresh compression of ``raw``."""
        self.lzma = pack_eva_lzma(raw)


@dataclass(slots=True)
class EVAImage:
    """Top-level container for a parsed or newly built EVA kernel image.

    ``records`` has length 1 for single-kernel images and length 2 for
    dual-kernel images; the invariant ``len(records) == 2 ⇔ dual_header
    is not None`` is checked by the parser and preserved by the builder.
    """

    records: list[TIRecord]
    dual_header: DualHeader | None = None
    signature: FileSignature | None = None
    legacy_padding: LegacyPadding = field(default_factory=LegacyPadding)

    @property
    def primary(self) -> TIRecord:
        return self.records[0]

    @property
    def secondary(self) -> TIRecord | None:
        return self.records[1] if len(self.records) > 1 else None

    @property
    def is_dual_kernel(self) -> bool:
        return self.dual_header is not None

    def validate(self, original_bytes: bytes | None = None) -> list[str]:
        """Return a list of checksum error messages, or ``[]`` if all clean.

        Pass ``original_bytes`` (the raw file this image was parsed from)
        to validate the outer file-signature CRC; otherwise that check is
        skipped because the CRC is computed over the exact bytes the file
        had on disk, which may differ from what :func:`build_image` would
        emit for the same logical image.
        """
        from eva_kernel_image.validator import validate_image

        return validate_image(self, original_bytes)
