"""Public exception hierarchy for eva_kernel_image."""

from __future__ import annotations


class FritzEvaError(Exception):
    """Base class for all eva_kernel_image exceptions."""


class ParseError(FritzEvaError):
    """Raised when an image cannot be parsed due to structural corruption.

    Examples: wrong magic at offset 0, truncated record, mismatched inner
    length fields. Checksum mismatches do *not* raise ``ParseError`` — they
    are reported by :func:`eva_kernel_image.validator.validate_image`.
    """


class BuildError(FritzEvaError):
    """Raised when an ``EVAImage`` cannot be serialised back to bytes.

    Examples: inconsistent ``dual_payload_length`` after a kernel replacement,
    missing required dual-header fields on a dual-kernel image.
    """


class LzmaCodecError(FritzEvaError):
    """Raised on LZMA encode/decode failures inside the EVA codec."""


class ValidationError(FritzEvaError):
    """Raised when strict validation is requested and the image has errors.

    The non-raising path is :func:`eva_kernel_image.validator.validate_image`, which
    returns a ``list[str]``. This exception is reserved for CLI or caller
    code that wants to turn the list into a hard failure.
    """
