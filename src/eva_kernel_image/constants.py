"""Magic numbers and fixed sizes for the Fritz!Box EVA kernel image format.

See ``docs/format-spec.md`` for the full specification.
"""

from __future__ import annotations

# Magic numbers (little-endian, as read from the file).
DUAL_KERNEL_MAGIC = 0xFEED9112
TI_AR7_MAGIC = 0xFEED1281
TI_AR7_2ND_MAGIC = 0xFEEDB007
EVA_LZMA_TYPE = 0x075A0201
SIGNATURE_MAGIC = 0xC453DE23

# Structure sizes in bytes.
TI_HEADER_SIZE = 12  # magic + payload_length + load_addr
TI_TRAILER_SIZE = 12  # checksum + zero + entry_addr
EVA_LZMA_HEADER_SIZE = 16  # type + compressed_len + uncompressed_len + data_checksum
EVA_LZMA_STREAM_HEADER_SIZE = 8  # properties(1) + dict_size(4) + padding(3)
FILE_SIGNATURE_SIZE = 8  # magic + crc

# LZMA compression parameters observed in every reference image.
EVA_LZMA_PROPERTIES = 0x5D  # lc=3, lp=0, pb=2
EVA_LZMA_DICT_SIZE = 0x00800000  # 8 MiB
