"""eva_kernel_image — parser, builder, and CLI for the Fritz!Box EVA kernel image format.

Public API (everything importable from ``eva_kernel_image`` directly)::

    parse_image(data: bytes) -> EVAImage
    build_image(image: EVAImage) -> bytes
    validate_image(image: EVAImage, original_bytes: bytes | None = None) -> list[str]

    pack_eva_lzma(raw: bytes) -> EVALzmaPayload
    unpack_eva_lzma(payload: EVALzmaPayload) -> bytes

    EVAImage, TIRecord, DualHeader, FileSignature, LegacyPadding, EVALzmaPayload

    ParseError, ValidationError, BuildError, LzmaCodecError, FritzEvaError

See ``docs/format-spec.md`` for the format this package implements.
"""

from __future__ import annotations

__version__ = "0.1.0"

from eva_kernel_image.builder import build_image, build_lzma_payload, build_ti_record
from eva_kernel_image.exceptions import (
    BuildError,
    FritzEvaError,
    LzmaCodecError,
    ParseError,
    ValidationError,
)
from eva_kernel_image.lzma_codec import EVALzmaPayload, pack_eva_lzma, unpack_eva_lzma
from eva_kernel_image.model import (
    DualHeader,
    EVAImage,
    FileSignature,
    LegacyPadding,
    TIRecord,
)
from eva_kernel_image.parser import parse_image
from eva_kernel_image.validator import validate_image

__all__ = [
    "BuildError",
    "DualHeader",
    "EVAImage",
    "EVALzmaPayload",
    "FileSignature",
    "FritzEvaError",
    "LegacyPadding",
    "LzmaCodecError",
    "ParseError",
    "TIRecord",
    "ValidationError",
    "__version__",
    "build_image",
    "build_lzma_payload",
    "build_ti_record",
    "pack_eva_lzma",
    "parse_image",
    "unpack_eva_lzma",
    "validate_image",
]
