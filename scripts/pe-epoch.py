#!/usr/bin/env python3
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Zeroes the build timestamps of Windows (PE) binaries, so a rebuild reproduces them.

    scripts/pe-epoch.py <binary> [binary ...]

The linker `cargo zigbuild` drives stamps the time it ran into the COFF header (`TimeDateStamp`)
and into every debug directory entry, and it accepts no flag that leaves them out. Two builds of
the same commit therefore differ in those bytes alone, and the independent rebuild could never
confirm a Windows binary (v0.1.10). Nothing reads them: Windows loads, verifies and runs the binary
the same with zero, which is what a reproducible linker writes.

Each file is rewritten in place, and only those fields; anything that is not a PE image is refused
rather than guessed at.
"""

import struct
import sys

PE_SIGNATURE = b"PE\0\0"
# The optional header's data directories start after its standard and Windows-specific fields.
DATA_DIRECTORIES_PE32 = 96
DATA_DIRECTORIES_PE32_PLUS = 112
PE32 = 0x10B
DEBUG_DIRECTORY = 6
DEBUG_ENTRY_BYTES = 28
SECTION_HEADER_BYTES = 40


def offset_of(image: bytearray, sections: int, count: int, rva: int):
    """The file offset of `rva`, through the section table."""
    for index in range(count):
        header = sections + SECTION_HEADER_BYTES * index
        virtual_size, virtual_address, _, raw_pointer = struct.unpack_from("<IIII", image, header + 8)
        if virtual_address <= rva < virtual_address + max(virtual_size, 1):
            return raw_pointer + (rva - virtual_address)
    return None


def zero_timestamps(image: bytearray) -> int:
    """Zeroes the COFF and debug directory timestamps of `image`; answers how many it zeroed."""
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    if image[:2] != b"MZ" or image[pe : pe + 4] != PE_SIGNATURE:
        raise ValueError("not a PE image")
    coff = pe + 4
    sections_count = struct.unpack_from("<H", image, coff + 2)[0]
    optional_size = struct.unpack_from("<H", image, coff + 16)[0]
    struct.pack_into("<I", image, coff + 4, 0)
    zeroed = 1

    optional = coff + 20
    magic = struct.unpack_from("<H", image, optional)[0]
    directories = optional + (DATA_DIRECTORIES_PE32 if magic == PE32 else DATA_DIRECTORIES_PE32_PLUS)
    sections = optional + optional_size
    rva, size = struct.unpack_from("<II", image, directories + 8 * DEBUG_DIRECTORY)
    if rva and size:
        at = offset_of(image, sections, sections_count, rva)
        if at is None:
            raise ValueError("the debug directory is outside every section")
        for entry in range(size // DEBUG_ENTRY_BYTES):
            struct.pack_into("<I", image, at + DEBUG_ENTRY_BYTES * entry + 4, 0)
            zeroed += 1
    return zeroed


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 64
    for path in sys.argv[1:]:
        with open(path, "rb") as file:
            image = bytearray(file.read())
        try:
            zeroed = zero_timestamps(image)
        except (ValueError, struct.error) as error:
            print(f"FAIL: {path}: {error}", file=sys.stderr)
            return 1
        with open(path, "wb") as file:
            file.write(image)
        print(f"ok: {path}: {zeroed} timestamps zeroed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
