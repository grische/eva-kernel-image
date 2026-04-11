"""Enable ``python -m eva_kernel_image`` as an alias for the ``eva-image`` CLI."""

from __future__ import annotations

import sys

from eva_kernel_image.cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
