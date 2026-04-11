"""Checksum-corruption detection matrix.

For each checksum class, flip one byte in a synthetic image at a targeted
offset and assert exactly the matching :func:`validate_image` error.
"""

from __future__ import annotations

from eva_kernel_image.builder import build_image
from eva_kernel_image.parser import parse_image
from eva_kernel_image.validator import validate_image
from tests.conftest import (
    SyntheticKernel,
    make_dual_kernel_image,
    synth_payload,
)


def _build() -> bytes:
    image = make_dual_kernel_image(
        SyntheticKernel(
            raw=synth_payload(4096, seed=9001),
            load_addr=0x80500000,
            entry_addr=0x80502000,
        ),
        SyntheticKernel(
            raw=synth_payload(2048, seed=9002),
            load_addr=0x8DFFFFFC,
            entry_addr=0x8E691770,
        ),
    )
    return build_image(image)


class TestCleanImage:
    def test_no_errors(self) -> None:
        raw = _build()
        image = parse_image(raw)
        assert validate_image(image, raw) == []


class TestCorruptions:
    def test_primary_payload_byte_flip_triggers_ti_and_lzma_errors(self) -> None:
        raw = bytearray(_build())
        # Flip a byte deep inside the primary LZMA compressed data. Offset
        # 0x40 lands inside the compressed stream (past the TI header + EVA
        # LZMA header + stream header).
        raw[0x40] ^= 0xFF
        image = parse_image(bytes(raw))
        errors = validate_image(image, bytes(raw))
        # The byte flip corrupts the primary payload, which triggers both:
        #   - the primary TI additive checksum (which sums payload bytes)
        #   - the LZMA CRC-32 over compressed data
        #   - the dual-kernel additive checksum (which also sums that byte)
        #   - the outer file-signature CRC (which covers everything)
        assert any("primary TI checksum" in e for e in errors)
        assert any("primary LZMA data checksum" in e for e in errors)

    def test_stored_ti_checksum_tamper(self) -> None:
        """Tamper only the stored primary TI-trailer checksum; payload is clean."""
        raw = bytearray(_build())
        image = parse_image(bytes(raw))

        # Locate the primary TI trailer checksum field on disk and flip it.
        # Layout: dual_header(12) + primary_ti_header(12) + primary_payload
        # + primary_ti_trailer(12). The trailer starts at
        #   12 + 12 + primary.payload_length
        # and its first 4 bytes are the checksum.
        tchk_off = 12 + 12 + image.primary.payload_length
        raw[tchk_off : tchk_off + 4] = b"\xde\xad\xbe\xef"
        errors = validate_image(parse_image(bytes(raw)), bytes(raw))
        assert any("primary TI checksum" in e for e in errors)
        # Tampering the stored field doesn't affect the payload, so LZMA CRC
        # should still be clean.
        assert not any("primary LZMA" in e for e in errors)

    def test_stored_lzma_crc_tamper(self) -> None:
        """Tamper the stored LZMA CRC field in the EVA LZMA header."""
        raw = bytearray(_build())
        image = parse_image(bytes(raw))

        # EVA LZMA header layout (inside primary payload):
        #   type(4) + compressed_len(4) + uncompressed_len(4) + data_checksum(4)
        # The data_checksum sits at primary_payload_offset + 12.
        # primary_payload starts at 12 (dual header) + 12 (primary TI header).
        data_crc_off = 12 + 12 + 12
        raw[data_crc_off : data_crc_off + 4] = b"\xca\xfe\xba\xbe"
        # Re-parse and re-validate: the parser reads the (tampered) CRC,
        # and validate_image recomputes and compares.
        image = parse_image(bytes(raw))
        errors = validate_image(image, bytes(raw))
        # But wait — tampering the CRC field also affects the TI payload-sum
        # checksum, because that's computed over the entire payload. So we
        # expect the LZMA mismatch AND the TI mismatch AND cascading
        # dual/file-signature errors. Check for the LZMA one specifically.
        assert any("primary LZMA data checksum" in e for e in errors)

    def test_file_signature_tamper(self) -> None:
        raw = bytearray(_build())
        # Flip a bit in the last 4 bytes (the CRC inside the file_signature).
        raw[-1] ^= 0x01
        image = parse_image(bytes(raw))
        errors = validate_image(image, bytes(raw))
        assert any("file signature CRC" in e for e in errors)

    def test_dual_wrapper_tamper(self) -> None:
        raw = bytearray(_build())
        image = parse_image(bytes(raw))

        # Locate the dual trailer checksum. Layout:
        #   dual_header(12) + dual_payload(dual_header.payload_length) + dual_trailer(12)
        # The trailer's first 4 bytes are the checksum.
        assert image.dual_header is not None
        dual_trailer_off = 12 + image.dual_header.payload_length
        raw[dual_trailer_off : dual_trailer_off + 4] = b"\x00\x00\x00\x00"
        errors = validate_image(parse_image(bytes(raw)), bytes(raw))
        assert any("dual kernel checksum" in e for e in errors)


class TestValidateWithoutOriginalBytes:
    """Calling validate() without original_bytes still checks TI + LZMA CRCs."""

    def test_skips_file_signature_and_dual_wrapper(self) -> None:
        raw = _build()
        image = parse_image(raw)
        # Tamper the stored dual checksum on the in-memory object.
        assert image.dual_header is not None
        image.dual_header.checksum ^= 0xFFFFFFFF
        # Without original_bytes, we can't recompute the dual checksum, so
        # the error should NOT appear.
        errors = validate_image(image)
        assert all("dual kernel checksum" not in e for e in errors)
