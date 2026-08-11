"""Shims for the supported interpreter range: the package runs on 3.8+."""

from __future__ import annotations

import sys

# ``dataclass(slots=True)`` is 3.10+, and a hand-written ``__slots__`` would clash
# with the class-level field defaults.
# Splatting allows the same decorator across all Python versions.
DATACLASS_SLOTS = {"slots": True} if sys.version_info >= (3, 10) else {}
