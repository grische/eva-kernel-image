"""Round-trip tests: parse then build must be byte-identical."""

from __future__ import annotations

from eva_kernel_image.builder import build_image
from eva_kernel_image.parser import parse_image
from tests.conftest import (
    SyntheticKernel,
    make_dual_kernel_image,
    make_single_kernel_image,
    synth_payload,
)


class TestSingleKernelRoundTrip:
    def test_parses_and_rebuilds_identically(self, single_image_bytes: bytes) -> None:
        image = parse_image(single_image_bytes)
        assert build_image(image) == single_image_bytes

    def test_parsed_structure_is_sane(self, single_image_bytes: bytes) -> None:
        image = parse_image(single_image_bytes)
        assert image.dual_header is None
        assert image.secondary is None
        assert len(image.records) == 1
        assert image.primary.load_addr == 0x80500000
        assert image.primary.entry_addr == 0x80502000

    def test_validates_clean(self, single_image_bytes: bytes) -> None:
        image = parse_image(single_image_bytes)
        assert image.validate(single_image_bytes) == []

    def test_decompress_matches_original(self) -> None:
        original = synth_payload(8192, seed=42)
        image = make_single_kernel_image(
            SyntheticKernel(raw=original, load_addr=0x80500000, entry_addr=0x80502000),
        )
        data = build_image(image)
        parsed = parse_image(data)
        assert parsed.primary.decompress() == original


class TestDualKernelRoundTrip:
    def test_parses_and_rebuilds_identically(self, dual_image_bytes: bytes) -> None:
        image = parse_image(dual_image_bytes)
        assert build_image(image) == dual_image_bytes

    def test_parsed_structure_is_sane(self, dual_image_bytes: bytes) -> None:
        image = parse_image(dual_image_bytes)
        assert image.dual_header is not None
        assert len(image.records) == 2
        assert image.primary.magic == 0xFEED1281
        assert image.secondary is not None
        assert image.secondary.magic == 0xFEEDB007
        assert image.primary.load_addr == 0x80500000
        assert image.secondary.load_addr == 0x8DFFFFFC

    def test_validates_clean(self, dual_image_bytes: bytes) -> None:
        image = parse_image(dual_image_bytes)
        assert image.validate(dual_image_bytes) == []

    def test_both_kernels_decompress(self) -> None:
        primary_raw = synth_payload(8192, seed=100)
        secondary_raw = synth_payload(4096, seed=101)
        image = make_dual_kernel_image(
            SyntheticKernel(raw=primary_raw, load_addr=0x80500000, entry_addr=0x80502000),
            SyntheticKernel(raw=secondary_raw, load_addr=0x8DFFFFFC, entry_addr=0x8E691770),
        )
        data = build_image(image)
        parsed = parse_image(data)
        assert parsed.primary.decompress() == primary_raw
        assert parsed.secondary is not None
        assert parsed.secondary.decompress() == secondary_raw


class TestDualWithLegacyTrailingBytes:
    def test_round_trips(self, dual_image_with_trailing_bytes: bytes) -> None:
        image = parse_image(dual_image_with_trailing_bytes)
        assert build_image(image) == dual_image_with_trailing_bytes

    def test_trailing_bytes_preserved(self, dual_image_with_trailing_bytes: bytes) -> None:
        image = parse_image(dual_image_with_trailing_bytes)
        assert image.legacy_padding.dual_trailing == b"\xab\xcd" * 32


class TestKernelReplacement:
    def test_replace_primary_produces_valid_image(self) -> None:
        image = make_dual_kernel_image(
            SyntheticKernel(
                raw=synth_payload(4096, seed=200),
                load_addr=0x80500000,
                entry_addr=0x80502000,
            ),
            SyntheticKernel(
                raw=synth_payload(2048, seed=201),
                load_addr=0x8DFFFFFC,
                entry_addr=0x8E691770,
            ),
        )
        # Initial build establishes the dual_payload_length field.
        build_image(image)

        new_primary = synth_payload(5000, seed=202)
        image.primary.replace_kernel(new_primary)

        # Recompute the fields the user is expected to update after a resize.
        from eva_kernel_image.constants import TI_HEADER_SIZE, TI_TRAILER_SIZE

        primary_wire = TI_HEADER_SIZE + image.primary.payload_length + TI_TRAILER_SIZE
        aligned = (primary_wire + 3) & ~3
        image.legacy_padding.inter_record = b"\x00" * (aligned - primary_wire)
        image.legacy_padding.dual_trailing = b""
        assert image.secondary is not None
        secondary_wire = TI_HEADER_SIZE + image.secondary.payload_length + TI_TRAILER_SIZE
        assert image.dual_header is not None
        image.dual_header.payload_length = (
            primary_wire + len(image.legacy_padding.inter_record) + secondary_wire
        )

        rebuilt = build_image(image)
        parsed = parse_image(rebuilt)
        assert parsed.primary.decompress() == new_primary
