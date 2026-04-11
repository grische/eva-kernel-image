"""Command-line interface for eva_kernel_image.

This module is intentionally thin: ``main()`` parses arguments, calls into
the library, and formats results for stdout/stderr. All business logic
lives in :mod:`eva_kernel_image.parser`, :mod:`eva_kernel_image.builder`,
:mod:`eva_kernel_image.validator`, and :mod:`eva_kernel_image.lzma_codec`.

Exit codes (documented in ``--help``):

=====  ==========================================================
  0    success
  1    parse error (structural corruption, wrong magic)
  2    validation error (checksum mismatch)
  3    I/O error
 64    CLI usage error (argparse default ``SystemExit``)
=====  ==========================================================
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from eva_kernel_image.builder import build_image, build_lzma_payload
from eva_kernel_image.constants import (
    DUAL_KERNEL_MAGIC,
    TI_AR7_2ND_MAGIC,
    TI_AR7_MAGIC,
    TI_HEADER_SIZE,
    TI_TRAILER_SIZE,
)
from eva_kernel_image.exceptions import BuildError, LzmaCodecError, ParseError
from eva_kernel_image.lzma_codec import pack_eva_lzma
from eva_kernel_image.model import (
    DualHeader,
    EVAImage,
    FileSignature,
    LegacyPadding,
    TIRecord,
)
from eva_kernel_image.parser import parse_image

EXIT_OK = 0
EXIT_PARSE = 1
EXIT_VALIDATION = 2
EXIT_IO = 3


def _format_ti_record(record: TIRecord, label: str) -> list[str]:
    lines = [
        f"  {label}:",
        f"    magic          = 0x{record.magic:08X}",
        f"    payload_length = {record.payload_length} (0x{record.payload_length:08X})",
        f"    load_addr      = 0x{record.load_addr:08X}",
        f"    entry_addr     = 0x{record.entry_addr:08X}",
        f"    checksum       = 0x{record.checksum:08X}",
        "    LZMA:",
        f"      compressed_len   = {record.lzma.compressed_len} "
        f"(0x{record.lzma.compressed_len:08X})",
        f"      uncompressed_len = {record.lzma.uncompressed_len} "
        f"(0x{record.lzma.uncompressed_len:08X})",
    ]
    ratio = (
        100.0 * record.lzma.compressed_len / record.lzma.uncompressed_len
        if record.lzma.uncompressed_len
        else 0.0
    )
    lines.extend(
        [
            f"      ratio            = {ratio:.1f}%",
            f"      data_checksum    = 0x{record.lzma.data_checksum:08X}",
            f"      properties       = 0x{record.lzma.properties:02X}",
            f"      dict_size        = 0x{record.lzma.dict_size:08X}",
            f"      stream_padding   = {record.lzma.stream_header_padding.hex()}",
        ],
    )
    return lines


def _ti_record_json(record: TIRecord) -> dict[str, object]:
    return {
        "magic": f"0x{record.magic:08X}",
        "payload_length": record.payload_length,
        "load_addr": f"0x{record.load_addr:08X}",
        "entry_addr": f"0x{record.entry_addr:08X}",
        "checksum": f"0x{record.checksum:08X}",
        "lzma": {
            "compressed_len": record.lzma.compressed_len,
            "uncompressed_len": record.lzma.uncompressed_len,
            "data_checksum": f"0x{record.lzma.data_checksum:08X}",
            "properties": f"0x{record.lzma.properties:02X}",
            "dict_size": f"0x{record.lzma.dict_size:08X}",
            "stream_header_padding": record.lzma.stream_header_padding.hex(),
        },
    }


def _image_to_json(image: EVAImage) -> dict[str, object]:
    out: dict[str, object] = {
        "is_dual_kernel": image.is_dual_kernel,
        "primary": _ti_record_json(image.primary),
        "post_data_padding_length": len(image.legacy_padding.post_data),
    }
    if image.signature is not None:
        out["signature_crc"] = f"0x{image.signature.crc:08X}"
    if image.dual_header is not None:
        assert image.secondary is not None
        out["secondary"] = _ti_record_json(image.secondary)
        out["dual_header"] = {
            "payload_length": image.dual_header.payload_length,
            "load_addr": f"0x{image.dual_header.load_addr:08X}",
            "entry_addr": f"0x{image.dual_header.entry_addr:08X}",
            "checksum": f"0x{image.dual_header.checksum:08X}",
        }
        out["inter_record_padding_hex"] = image.legacy_padding.inter_record.hex()
        out["dual_trailing_bytes_hex"] = image.legacy_padding.dual_trailing.hex()
    return out


def _read_image(path: Path, *, out: object) -> tuple[bytes, EVAImage] | int:
    try:
        data = path.read_bytes()
    except OSError as exc:
        print(f"ERROR: failed to read {path}: {exc}", file=sys.stderr)
        return EXIT_IO
    try:
        image = parse_image(data)
    except ParseError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_PARSE
    return data, image


def cmd_info(image_path: str) -> int:
    result = _read_image(Path(image_path), out=sys.stdout)
    if isinstance(result, int):
        return result
    data, image = result

    print(f"File: {image_path}")
    print(f"Size: {len(data)} bytes")
    print(f"Format: {'dual-kernel' if image.is_dual_kernel else 'single-kernel'}")
    print()
    if image.dual_header is not None:
        print("Dual kernel wrapper:")
        print(f"  magic          = 0x{DUAL_KERNEL_MAGIC:08X}")
        print(
            f"  payload_length = {image.dual_header.payload_length} "
            f"(0x{image.dual_header.payload_length:08X})",
        )
        print(f"  load_addr      = 0x{image.dual_header.load_addr:08X}")
        print(f"  entry_addr     = 0x{image.dual_header.entry_addr:08X}")
        print(f"  checksum       = 0x{image.dual_header.checksum:08X}")
        print()

    for line in _format_ti_record(image.primary, "Primary TI record"):
        print(line)
    if image.secondary is not None:
        print()
        for line in _format_ti_record(image.secondary, "Secondary TI record"):
            print(line)
    print()
    print(f"Inter-record padding: {len(image.legacy_padding.inter_record)} bytes")
    print(f"Post-data padding:    {len(image.legacy_padding.post_data)} bytes")
    if image.legacy_padding.dual_trailing:
        print(f"Dual trailing bytes:  {len(image.legacy_padding.dual_trailing)} bytes")
    if image.signature is not None:
        print(f"File signature CRC:   0x{image.signature.crc:08X}")
    print()

    errors = image.validate(data)
    if errors:
        print("CHECKSUM ERRORS:")
        for err in errors:
            print(f"  ! {err}")
        return EXIT_VALIDATION
    print("All checksums valid.")
    return EXIT_OK


def cmd_verify(image_path: str, *, verbose: bool = False) -> int:
    result = _read_image(Path(image_path), out=sys.stdout)
    if isinstance(result, int):
        return result
    data, image = result
    errors = image.validate(data)
    if errors:
        if verbose:
            for err in errors:
                print(f"  ! {err}", file=sys.stderr)
        return EXIT_VALIDATION
    return EXIT_OK


def cmd_extract(image_path: str, output_dir: str | None) -> int:
    result = _read_image(Path(image_path), out=sys.stdout)
    if isinstance(result, int):
        return result
    data, image = result

    out_dir = Path(output_dir) if output_dir else Path(image_path + ".extracted")
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"ERROR: failed to create {out_dir}: {exc}", file=sys.stderr)
        return EXIT_IO

    # Primary kernel
    (out_dir / "kernel1.lzma").write_bytes(build_lzma_payload(image.primary.lzma))
    try:
        kernel1_raw = image.primary.decompress()
        (out_dir / "kernel1.bin").write_bytes(kernel1_raw)
        print(f"Extracted kernel1.bin ({len(kernel1_raw)} bytes)")
    except LzmaCodecError as exc:
        print(f"WARNING: failed to decompress primary kernel: {exc}", file=sys.stderr)

    if image.secondary is not None:
        (out_dir / "kernel2.lzma").write_bytes(build_lzma_payload(image.secondary.lzma))
        try:
            kernel2_raw = image.secondary.decompress()
            (out_dir / "kernel2.bin").write_bytes(kernel2_raw)
            print(f"Extracted kernel2.bin ({len(kernel2_raw)} bytes)")
        except LzmaCodecError as exc:
            print(f"WARNING: failed to decompress secondary kernel: {exc}", file=sys.stderr)

    metadata = _image_to_json(image)
    metadata["source_file"] = str(image_path)
    metadata["source_size"] = len(data)
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))

    # Preserve legacy padding bytes verbatim so `repack` from this directory
    # can reproduce the original image byte-for-byte.
    (out_dir / "inter_record_padding.bin").write_bytes(image.legacy_padding.inter_record)
    (out_dir / "post_data_padding.bin").write_bytes(image.legacy_padding.post_data)
    if image.legacy_padding.dual_trailing:
        (out_dir / "dual_trailing_bytes.bin").write_bytes(image.legacy_padding.dual_trailing)

    print(f"Extracted to: {out_dir}")
    errors = image.validate(data)
    if errors:
        print("CHECKSUM WARNINGS:", file=sys.stderr)
        for err in errors:
            print(f"  ! {err}", file=sys.stderr)
    return EXIT_OK


def cmd_repack(
    image_path: str,
    output: str,
    kernel1: str | None,
    kernel2: str | None,
) -> int:
    result = _read_image(Path(image_path), out=sys.stdout)
    if isinstance(result, int):
        return result
    _data, image = result

    kernels_replaced = False

    if kernel1 is not None:
        try:
            new_kernel1 = Path(kernel1).read_bytes()
        except OSError as exc:
            print(f"ERROR: failed to read {kernel1}: {exc}", file=sys.stderr)
            return EXIT_IO
        original_kernel1 = image.primary.decompress()
        if new_kernel1 != original_kernel1:
            print(f"Recompressing primary kernel ({len(new_kernel1)} bytes)...")
            image.primary.replace_kernel(new_kernel1)
            kernels_replaced = True
        else:
            print("Primary kernel unchanged — reusing original compressed data.")

    if kernel2 is not None:
        if image.secondary is None:
            print("ERROR: --kernel2 given but image is single-kernel", file=sys.stderr)
            return EXIT_PARSE
        try:
            new_kernel2 = Path(kernel2).read_bytes()
        except OSError as exc:
            print(f"ERROR: failed to read {kernel2}: {exc}", file=sys.stderr)
            return EXIT_IO
        original_kernel2 = image.secondary.decompress()
        if new_kernel2 != original_kernel2:
            print(f"Recompressing secondary kernel ({len(new_kernel2)} bytes)...")
            image.secondary.replace_kernel(new_kernel2)
            kernels_replaced = True
        else:
            print("Secondary kernel unchanged — reusing original compressed data.")

    if kernels_replaced and image.dual_header is not None:
        assert image.secondary is not None
        primary_wire = TI_HEADER_SIZE + image.primary.payload_length + TI_TRAILER_SIZE
        aligned = (primary_wire + 3) & ~3
        image.legacy_padding.inter_record = b"\x00" * (aligned - primary_wire)
        image.legacy_padding.dual_trailing = b""
        secondary_wire = TI_HEADER_SIZE + image.secondary.payload_length + TI_TRAILER_SIZE
        image.dual_header.payload_length = (
            primary_wire + len(image.legacy_padding.inter_record) + secondary_wire
        )

    try:
        output_bytes = build_image(image)
    except BuildError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_PARSE
    try:
        Path(output).write_bytes(output_bytes)
    except OSError as exc:
        print(f"ERROR: failed to write {output}: {exc}", file=sys.stderr)
        return EXIT_IO
    print(f"Wrote {output} ({len(output_bytes)} bytes)")
    return EXIT_OK


def cmd_pack(
    output: str,
    kernel1: str,
    load1: int,
    entry1: int,
    kernel2: str | None,
    load2: int | None,
    entry2: int | None,
    dual_load: int | None,
) -> int:
    try:
        raw1 = Path(kernel1).read_bytes()
    except OSError as exc:
        print(f"ERROR: failed to read {kernel1}: {exc}", file=sys.stderr)
        return EXIT_IO
    print(f"Compressing primary kernel ({len(raw1)} bytes)...")
    lzma1 = pack_eva_lzma(raw1)
    primary = TIRecord(
        magic=TI_AR7_MAGIC,
        load_addr=load1,
        entry_addr=entry1,
        checksum=0,
        lzma=lzma1,
    )

    if kernel2 is not None:
        if load2 is None or entry2 is None:
            print(
                "ERROR: --load2 and --entry2 are required when --kernel2 is given",
                file=sys.stderr,
            )
            return EXIT_PARSE
        try:
            raw2 = Path(kernel2).read_bytes()
        except OSError as exc:
            print(f"ERROR: failed to read {kernel2}: {exc}", file=sys.stderr)
            return EXIT_IO
        print(f"Compressing secondary kernel ({len(raw2)} bytes)...")
        lzma2 = pack_eva_lzma(raw2)
        secondary = TIRecord(
            magic=TI_AR7_2ND_MAGIC,
            load_addr=load2,
            entry_addr=entry2,
            checksum=0,
            lzma=lzma2,
        )

        primary_wire = TI_HEADER_SIZE + primary.payload_length + TI_TRAILER_SIZE
        aligned = (primary_wire + 3) & ~3
        inter_padding = b"\x00" * (aligned - primary_wire)
        secondary_wire = TI_HEADER_SIZE + secondary.payload_length + TI_TRAILER_SIZE
        dual_payload_length = primary_wire + len(inter_padding) + secondary_wire

        image = EVAImage(
            records=[primary, secondary],
            dual_header=DualHeader(
                payload_length=dual_payload_length,
                load_addr=dual_load if dual_load is not None else load1,
                entry_addr=entry1,
                checksum=0,
            ),
            signature=FileSignature(crc=0),
            legacy_padding=LegacyPadding(inter_record=inter_padding),
        )
    else:
        image = EVAImage(
            records=[primary],
            dual_header=None,
            signature=None,
            legacy_padding=LegacyPadding(),
        )

    try:
        output_bytes = build_image(image)
    except BuildError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_PARSE
    try:
        Path(output).write_bytes(output_bytes)
    except OSError as exc:
        print(f"ERROR: failed to write {output}: {exc}", file=sys.stderr)
        return EXIT_IO
    print(f"Wrote {output} ({len(output_bytes)} bytes)")
    return EXIT_OK


def _parse_addr(s: str) -> int:
    return int(s, 0)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eva-image",
        description="Fritz!Box EVA kernel image tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_info = subparsers.add_parser("info", help="print image metadata and validate checksums")
    p_info.add_argument("image", help="EVA kernel image file")

    p_verify = subparsers.add_parser(
        "verify",
        help="validate checksums, exit non-zero on any mismatch (quiet)",
    )
    p_verify.add_argument("image", help="EVA kernel image file")
    p_verify.add_argument("-v", "--verbose", action="store_true", help="print errors on stderr")

    p_extract = subparsers.add_parser("extract", help="extract kernels and metadata")
    p_extract.add_argument("image", help="EVA kernel image file")
    p_extract.add_argument("-o", "--output", help="output directory (default: <image>.extracted)")

    p_repack = subparsers.add_parser(
        "repack",
        help="rebuild an image, optionally replacing kernel(s)",
    )
    p_repack.add_argument("image", help="original EVA kernel image (used as template)")
    p_repack.add_argument("-o", "--output", required=True, help="output image file")
    p_repack.add_argument("--kernel1", help="replacement primary kernel (raw binary)")
    p_repack.add_argument("--kernel2", help="replacement secondary kernel (raw binary)")

    p_pack = subparsers.add_parser("pack", help="build an image from raw kernel binaries")
    p_pack.add_argument("-o", "--output", required=True, help="output image file")
    p_pack.add_argument("--kernel1", required=True, help="primary kernel (raw binary)")
    p_pack.add_argument("--kernel2", help="secondary kernel (raw binary); omit for single-kernel")
    p_pack.add_argument("--load1", type=_parse_addr, required=True, help="primary load address")
    p_pack.add_argument("--entry1", type=_parse_addr, required=True, help="primary entry address")
    p_pack.add_argument("--load2", type=_parse_addr, help="secondary load address")
    p_pack.add_argument("--entry2", type=_parse_addr, help="secondary entry address")
    p_pack.add_argument(
        "--dual-load",
        type=_parse_addr,
        help="dual header load address (defaults to --load1)",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "info":
        return cmd_info(args.image)
    if args.command == "verify":
        return cmd_verify(args.image, verbose=args.verbose)
    if args.command == "extract":
        return cmd_extract(args.image, args.output)
    if args.command == "repack":
        return cmd_repack(args.image, args.output, args.kernel1, args.kernel2)
    if args.command == "pack":
        return cmd_pack(
            args.output,
            args.kernel1,
            args.load1,
            args.entry1,
            args.kernel2,
            args.load2,
            args.entry2,
            args.dual_load,
        )
    # argparse with required=True should make this unreachable.
    parser.print_help(sys.stderr)
    return 64
