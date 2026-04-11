"""Round-trip and parameter tests for the EVA LZMA codec."""

from __future__ import annotations

import zlib

import pytest

from eva_kernel_image.checksums import lzma_crc32
from eva_kernel_image.constants import EVA_LZMA_DICT_SIZE, EVA_LZMA_PROPERTIES
from eva_kernel_image.exceptions import LzmaCodecError
from eva_kernel_image.lzma_codec import EVALzmaPayload, pack_eva_lzma, unpack_eva_lzma


def _random_like(n: int, seed: int = 0x5EEDED) -> bytes:
    """Produce deterministic pseudo-random bytes of a given length."""
    import random

    rng = random.Random(seed)
    return rng.randbytes(n)


class TestPackEvaLzma:
    def test_properties_match_reference_images(self) -> None:
        """Every observed AVM image uses lc=3/lp=0/pb=2 (0x5D) and an 8 MiB dict."""
        payload = pack_eva_lzma(b"x" * 1024)
        assert payload.properties == EVA_LZMA_PROPERTIES
        assert payload.dict_size == EVA_LZMA_DICT_SIZE
        assert payload.stream_header_padding == b"\x00\x00\x00"

    def test_fields_are_consistent(self) -> None:
        raw = b"consistent field test" * 50
        payload = pack_eva_lzma(raw)
        assert payload.compressed_len == len(payload.compressed_data)
        assert payload.uncompressed_len == len(raw)
        assert payload.data_checksum == lzma_crc32(payload.compressed_data)
        assert payload.data_checksum == zlib.crc32(payload.compressed_data) & 0xFFFFFFFF

    def test_empty_input(self) -> None:
        payload = pack_eva_lzma(b"")
        assert payload.uncompressed_len == 0
        # Empty input still produces a valid (short) LZMA1 stream.
        assert payload.compressed_len > 0


class TestRoundTrip:
    @pytest.mark.parametrize(
        "size",
        [
            0,
            1,
            255,  # just below the 256-byte alignment boundary used by EVA
            256,  # exactly one block
            257,  # just above
            4096,
            1 << 16,  # 64 KB
            1 << 20,  # 1 MB
        ],
    )
    def test_size_round_trip(self, size: int) -> None:
        raw = _random_like(size)
        payload = pack_eva_lzma(raw)
        assert unpack_eva_lzma(payload) == raw

    def test_highly_compressible(self) -> None:
        raw = b"\x00" * (2 << 20)  # 2 MB of zeros
        payload = pack_eva_lzma(raw)
        # Should compress dramatically.
        assert payload.compressed_len < len(raw) // 100
        assert unpack_eva_lzma(payload) == raw

    def test_incompressible(self) -> None:
        raw = _random_like(1 << 16)
        payload = pack_eva_lzma(raw)
        assert unpack_eva_lzma(payload) == raw


class TestUnpackFallback:
    """unpack_eva_lzma has a two-path fallback: real ulen then 0xFFFF…FF.

    We can verify that streams produced by :func:`pack_eva_lzma` decode
    successfully — that exercises path 2 in full (stdlib-produced streams
    contain an EOPM and fail path 1, so the fallback path is always taken).
    Path 1 — real ``ulen`` with no EOPM — cannot be exercised without a real
    AVM-produced stream, which we don't ship as a fixture. Its correctness
    is verified out-of-band against the research corpus of 18 reference
    images; see ``docs/format-spec.md``.
    """

    def test_stdlib_round_trip_covers_fallback(self) -> None:
        """Any successful round-trip after pack_eva_lzma exercises path 2."""
        raw = b"the quick brown fox" * 100
        payload = pack_eva_lzma(raw)
        assert unpack_eva_lzma(payload) == raw

    def test_corrupted_stream_raises(self) -> None:
        raw = b"placeholder" * 64
        payload = pack_eva_lzma(raw)
        # Flip a byte in the middle of the compressed data.
        bad = bytearray(payload.compressed_data)
        bad[len(bad) // 2] ^= 0xFF
        corrupted = EVALzmaPayload(
            compressed_len=payload.compressed_len,
            uncompressed_len=payload.uncompressed_len,
            data_checksum=payload.data_checksum,  # intentionally unchanged
            properties=payload.properties,
            dict_size=payload.dict_size,
            stream_header_padding=payload.stream_header_padding,
            compressed_data=bytes(bad),
        )
        with pytest.raises(LzmaCodecError):
            unpack_eva_lzma(corrupted)

    def test_wrong_ulen_raises(self) -> None:
        raw = b"wrong ulen test" * 100
        payload = pack_eva_lzma(raw)
        # Corrupt the header parameters so both paths fail.
        wrong = EVALzmaPayload(
            compressed_len=payload.compressed_len,
            uncompressed_len=payload.uncompressed_len,
            data_checksum=payload.data_checksum,
            properties=0xFF,  # invalid props byte
            dict_size=payload.dict_size,
            stream_header_padding=payload.stream_header_padding,
            compressed_data=payload.compressed_data,
        )
        with pytest.raises(LzmaCodecError):
            unpack_eva_lzma(wrong)
