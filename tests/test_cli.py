"""Smoke tests for the ``eva-image`` CLI.

All tests run against synthetic images built via ``tests.conftest``. They
exercise :func:`eva_kernel_image.cli.main` directly, without spawning subprocesses.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from eva_kernel_image.cli import main


class TestInfo:
    def test_reports_clean_single_image(
        self,
        single_image_bytes: bytes,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        f = tmp_path / "single.image"
        f.write_bytes(single_image_bytes)
        rc = main(["info", str(f)])
        out = capsys.readouterr().out
        assert rc == 0
        assert "single-kernel" in out
        assert "All checksums valid." in out

    def test_reports_clean_dual_image(
        self,
        dual_image_bytes: bytes,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        f = tmp_path / "dual.image"
        f.write_bytes(dual_image_bytes)
        rc = main(["info", str(f)])
        out = capsys.readouterr().out
        assert rc == 0
        assert "dual-kernel" in out
        assert "Primary TI record" in out
        assert "Secondary TI record" in out
        assert "All checksums valid." in out

    def test_parse_error_exits_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        f = tmp_path / "garbage.image"
        f.write_bytes(b"\xff" * 128)
        rc = main(["info", str(f)])
        err = capsys.readouterr().err
        assert rc == 1
        assert "ERROR" in err


class TestVerify:
    def test_clean_exits_0_silently(
        self,
        dual_image_bytes: bytes,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        f = tmp_path / "dual.image"
        f.write_bytes(dual_image_bytes)
        rc = main(["verify", str(f)])
        assert rc == 0
        out = capsys.readouterr()
        assert out.out == ""
        assert out.err == ""

    def test_corrupted_exits_2(
        self,
        dual_image_bytes: bytes,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        raw = bytearray(dual_image_bytes)
        raw[-1] ^= 0x01  # flip file signature CRC
        f = tmp_path / "tampered.image"
        f.write_bytes(bytes(raw))
        rc = main(["verify", str(f), "-v"])
        err = capsys.readouterr().err
        assert rc == 2
        assert "file signature CRC" in err


class TestExtract:
    def test_extract_dual(
        self,
        dual_image_bytes: bytes,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        f = tmp_path / "dual.image"
        f.write_bytes(dual_image_bytes)
        out_dir = tmp_path / "out"
        rc = main(["extract", str(f), "-o", str(out_dir)])
        assert rc == 0
        assert (out_dir / "kernel1.bin").exists()
        assert (out_dir / "kernel1.lzma").exists()
        assert (out_dir / "kernel2.bin").exists()
        assert (out_dir / "kernel2.lzma").exists()
        meta = json.loads((out_dir / "metadata.json").read_text())
        assert meta["is_dual_kernel"] is True
        assert "primary" in meta
        assert "secondary" in meta


class TestRepack:
    def test_repack_no_replacement_byte_identical(
        self,
        dual_image_bytes: bytes,
        tmp_path: Path,
    ) -> None:
        src = tmp_path / "src.image"
        src.write_bytes(dual_image_bytes)
        dst = tmp_path / "dst.image"
        rc = main(["repack", str(src), "-o", str(dst)])
        assert rc == 0
        assert dst.read_bytes() == dual_image_bytes

    def test_repack_with_replacement_boots_round_trip(
        self,
        dual_image_bytes: bytes,
        tmp_path: Path,
    ) -> None:
        from eva_kernel_image.parser import parse_image

        src = tmp_path / "src.image"
        src.write_bytes(dual_image_bytes)

        new_primary = b"replacement primary kernel content" * 100
        new_primary_file = tmp_path / "new_primary.bin"
        new_primary_file.write_bytes(new_primary)

        dst = tmp_path / "patched.image"
        rc = main(
            [
                "repack",
                str(src),
                "-o",
                str(dst),
                "--kernel1",
                str(new_primary_file),
            ],
        )
        assert rc == 0
        parsed = parse_image(dst.read_bytes())
        assert parsed.primary.decompress() == new_primary


class TestPack:
    def test_pack_single_kernel_from_raw(self, tmp_path: Path) -> None:
        from eva_kernel_image.parser import parse_image

        raw = b"single kernel pack test" * 200
        raw_file = tmp_path / "kernel.bin"
        raw_file.write_bytes(raw)

        out = tmp_path / "packed.image"
        rc = main(
            [
                "pack",
                "-o",
                str(out),
                "--kernel1",
                str(raw_file),
                "--load1",
                "0x80500000",
                "--entry1",
                "0x80502000",
            ],
        )
        assert rc == 0
        parsed = parse_image(out.read_bytes())
        assert parsed.dual_header is None
        assert parsed.primary.decompress() == raw
        assert parsed.primary.load_addr == 0x80500000
        assert parsed.primary.entry_addr == 0x80502000

    def test_pack_dual_kernel_from_raw(self, tmp_path: Path) -> None:
        from eva_kernel_image.parser import parse_image

        raw1 = b"primary content " * 300
        raw2 = b"secondary content " * 200
        f1 = tmp_path / "k1.bin"
        f2 = tmp_path / "k2.bin"
        f1.write_bytes(raw1)
        f2.write_bytes(raw2)

        out = tmp_path / "dual.image"
        rc = main(
            [
                "pack",
                "-o",
                str(out),
                "--kernel1",
                str(f1),
                "--kernel2",
                str(f2),
                "--load1",
                "0x80500000",
                "--entry1",
                "0x80502000",
                "--load2",
                "0x8DFFFFFC",
                "--entry2",
                "0x8E691770",
            ],
        )
        assert rc == 0
        parsed = parse_image(out.read_bytes())
        assert parsed.dual_header is not None
        assert parsed.primary.decompress() == raw1
        assert parsed.secondary is not None
        assert parsed.secondary.decompress() == raw2
