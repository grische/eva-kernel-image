# eva-image-tool

[![PyPI](https://img.shields.io/pypi/v/eva-kernel-image.svg)](https://pypi.org/project/eva-kernel-image/)
[![Python](https://img.shields.io/pypi/pyversions/eva-kernel-image.svg)](https://pypi.org/project/eva-kernel-image/)
[![License](https://img.shields.io/pypi/l/eva-kernel-image.svg)](LICENSE)

Parser, builder, and CLI for the **Fritz!Box EVA kernel image format** — the
`TI record` container used by AVM's EVA bootloader to hold LZMA-compressed
Linux kernels. Pure Python standard library, zero runtime dependencies.

See [`docs/format-spec.md`](docs/format-spec.md) for the full format
specification and [`docs/format-quickref.md`](docs/format-quickref.md) for a
one-page summary.

## Install

```sh
pipx install eva-kernel-image     # recommended for CLI-only use
pip  install eva-kernel-image     # for library use
```

No external binaries required — everything runs on Python's stdlib `lzma`,
`zlib`, `struct`, and `argparse`.

## CLI quickstart

```sh
# Inspect an image
eva-image info kernel.image

# Verify checksums (exit 0 if valid, non-zero otherwise)
eva-image verify kernel.image

# Extract kernels + metadata.json to a directory
eva-image extract kernel.image -o extracted/

# Rebuild an image, optionally replacing kernel(s)
eva-image repack kernel.image -o new.image
eva-image repack kernel.image -o new.image \
    --kernel1 patched-primary.bin

# Pack an image from raw kernel binaries
eva-image pack -o new.image \
    --kernel1 kernel1.bin --load1 0x80500000 --entry1 0x80C8B500 \
    --kernel2 kernel2.bin --load2 0x8DFFFFFC --entry2 0x8E691770
```

## Library quickstart

```python
from pathlib import Path
from eva_kernel_image import parse_image, build_image

image = parse_image(Path("kernel.image").read_bytes())

print(f"dual-kernel: {image.dual_header is not None}")
print(f"primary entry: 0x{image.primary.entry_addr:08X}")
print(f"primary uncompressed size: {image.primary.lzma.uncompressed_len}")

# Validate checksums (parser itself does not auto-validate)
for issue in image.validate():
    print(f"warning: {issue}")

# Decompress a kernel
Path("kernel1.bin").write_bytes(image.primary.decompress())

# Replace a kernel and rebuild
image.primary.replace_kernel(Path("patched.bin").read_bytes())
Path("patched.kernel.image").write_bytes(build_image(image))
```

## Supported models

Verified against 18 reference images spanning six product lines:

| Model       | Firmware versions tested               |
|-------------|----------------------------------------|
| 7530        | 08.02                                  |
| 7560        | 07.00, 07.12, 07.27, 07.29, 07.30      |
| 7580        | 06.92, 07.27, 07.30                    |
| 7583        | 08.03                                  |
| 7590        | 08.03, 08.10                           |
| 7590 AX     | 08.02                                  |

Both single-kernel (`FEED1281`) and dual-kernel (`FEED9112`) variants are
handled, including the legacy inner-signature quirk found on older
Fritz!Box 7560 and 7580 builds.

## License

see [LICENSE](LICENSE).
