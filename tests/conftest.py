"""Shared test fixtures: synthetic EVA kernel image factory.

Tests build small valid images in-memory rather than loading AVM firmware
binaries from disk — this keeps the test suite self-contained (no copyrighted
blobs checked in) and fast.

The factory uses the library's own builder, so any change to the builder
immediately propagates to the test fixtures. The tests then parse those
bytes back and check structural invariants. This catches bugs on either
side of the parse ↔ build boundary.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from eva_kernel_image.builder import build_image
from eva_kernel_image.constants import (
    TI_AR7_2ND_MAGIC,
    TI_AR7_MAGIC,
    TI_HEADER_SIZE,
    TI_TRAILER_SIZE,
)
from eva_kernel_image.lzma_codec import pack_eva_lzma
from eva_kernel_image.model import (
    DualHeader,
    EVAImage,
    FileSignature,
    LegacyPadding,
    TIRecord,
)


@dataclass
class SyntheticKernel:
    """A raw kernel plus the addresses it will be placed at."""

    raw: bytes
    load_addr: int
    entry_addr: int


def _make_record(kernel: SyntheticKernel, magic: int) -> TIRecord:
    lzma = pack_eva_lzma(kernel.raw)
    return TIRecord(
        magic=magic,
        load_addr=kernel.load_addr,
        entry_addr=kernel.entry_addr,
        checksum=0,  # builder recomputes
        lzma=lzma,
    )


def make_single_kernel_image(
    primary: SyntheticKernel,
    *,
    with_signature: bool = True,
    post_data_padding: bytes = b"",
) -> EVAImage:
    """Build a valid single-kernel image in-memory."""
    record = _make_record(primary, TI_AR7_MAGIC)
    return EVAImage(
        records=[record],
        dual_header=None,
        signature=FileSignature(crc=0) if with_signature else None,
        legacy_padding=LegacyPadding(post_data=post_data_padding),
    )


def make_dual_kernel_image(
    primary: SyntheticKernel,
    secondary: SyntheticKernel,
    *,
    dual_trailing: bytes = b"",
    post_data_padding: bytes = b"",
) -> EVAImage:
    """Build a valid dual-kernel image in-memory.

    ``dual_trailing`` mimics the legacy inner-signature quirk on older 7560
    and 7580 builds. ``post_data_padding`` adds zero fill between the dual
    trailer and the file signature (some images do).
    """
    primary_rec = _make_record(primary, TI_AR7_MAGIC)
    secondary_rec = _make_record(secondary, TI_AR7_2ND_MAGIC)

    # Compute dual_payload_length so the builder's invariant check passes.
    primary_wire_len = TI_HEADER_SIZE + primary_rec.payload_length + TI_TRAILER_SIZE
    secondary_wire_len = TI_HEADER_SIZE + secondary_rec.payload_length + TI_TRAILER_SIZE

    # 4-byte alignment padding between records.
    aligned = (primary_wire_len + 3) & ~3
    inter_pad = b"\x00" * (aligned - primary_wire_len)

    dual_payload_length = (
        primary_wire_len + len(inter_pad) + secondary_wire_len + len(dual_trailing)
    )

    return EVAImage(
        records=[primary_rec, secondary_rec],
        dual_header=DualHeader(
            payload_length=dual_payload_length,
            load_addr=primary.load_addr,
            entry_addr=primary.entry_addr,
            checksum=0,  # builder recomputes
        ),
        signature=FileSignature(crc=0),
        legacy_padding=LegacyPadding(
            inter_record=inter_pad,
            dual_trailing=dual_trailing,
            post_data=post_data_padding,
        ),
    )


def synth_payload(n: int, seed: int = 0xBEEF) -> bytes:
    """Deterministic ~random bytes for use as a synthetic kernel body."""
    import random

    return random.Random(seed).randbytes(n)


def primary_kernel(size: int, seed: int) -> SyntheticKernel:
    """Convenience factory matching the load/entry addresses from real 7560 images."""
    return SyntheticKernel(
        raw=synth_payload(size, seed=seed),
        load_addr=0x80500000,
        entry_addr=0x80502000,
    )


def secondary_kernel(size: int, seed: int) -> SyntheticKernel:
    """Convenience factory matching the load/entry addresses from real 7560 images."""
    return SyntheticKernel(
        raw=synth_payload(size, seed=seed),
        load_addr=0x8DFFFFFC,
        entry_addr=0x8E691770,
    )


@pytest.fixture
def single_image_bytes() -> bytes:
    """A minimal valid single-kernel image."""
    image = make_single_kernel_image(primary_kernel(4096, seed=1))
    return build_image(image)


@pytest.fixture
def dual_image_bytes() -> bytes:
    """A minimal valid dual-kernel image (no legacy trailing bytes)."""
    image = make_dual_kernel_image(
        primary_kernel(4096, seed=2),
        secondary_kernel(2048, seed=3),
    )
    return build_image(image)


@pytest.fixture
def dual_image_with_trailing_bytes() -> bytes:
    """A dual-kernel image with legacy trailing bytes between records and trailer."""
    image = make_dual_kernel_image(
        primary_kernel(4096, seed=4),
        secondary_kernel(2048, seed=5),
        dual_trailing=b"\xab\xcd" * 32,  # 64 bytes of non-zero trailing data
    )
    return build_image(image)


# Re-export helpers so tests can build custom images directly.
__all__ = [
    "SyntheticKernel",
    "make_dual_kernel_image",
    "make_single_kernel_image",
    "primary_kernel",
    "secondary_kernel",
    "synth_payload",
]
