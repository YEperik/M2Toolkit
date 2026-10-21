#!/usr/bin/env python3
"""Synthetic tests for the PACKAGE.BIN global + regular descriptor layout."""
from __future__ import annotations
import importlib.util
import pathlib
import struct
import sys


def load_module(path: pathlib.Path):
    spec = importlib.util.spec_from_file_location("map_package_assets", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load map_package_assets.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def make_valid_package() -> bytes:
    data = bytearray(0x80)
    # Header: descriptor table ends at 0x40; global A/B are 0x10 each.
    struct.pack_into("<3I", data, 0, 0x40, 0x10, 0x10)
    # One regular descriptor begins exactly after global data and ends at EOF.
    struct.pack_into("<8I", data, 0x20, 0x60, 0x10, 0x10, 0, 0, 0, 0, 0)
    return bytes(data)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: test_package_layout.py map_package_assets.py", file=sys.stderr)
        return 2
    module = load_module(pathlib.Path(sys.argv[1]))
    package = make_valid_package()
    global_desc, descs, header = module.parse_descriptors(package)
    assert global_desc.start == 0x40
    assert global_desc.size_a == 0x10
    assert global_desc.size_b == 0x10
    assert global_desc.end == 0x60
    assert header["descriptor_table_end"] == 0x40
    assert len(descs) == 1 and descs[0].start == 0x60 and descs[0].end == len(package)

    malformed = bytearray(package)
    struct.pack_into("<I", malformed, 0x20, 0x61)
    try:
        module.parse_descriptors(bytes(malformed))
    except ValueError:
        pass
    else:
        raise AssertionError("non-contiguous descriptor was accepted")

    malformed = bytearray(package)
    struct.pack_into("<I", malformed, 0x28, 0x21)  # regular size B makes end exceed EOF
    try:
        module.parse_descriptors(bytes(malformed))
    except ValueError:
        pass
    else:
        raise AssertionError("descriptor extending beyond file was accepted")

    malformed = bytearray(package)
    struct.pack_into("<I", malformed, 0, 0x41)  # table end not aligned to 32-byte records
    try:
        module.parse_descriptors(bytes(malformed))
    except ValueError:
        pass
    else:
        raise AssertionError("misaligned descriptor table end was accepted")

    print("PASS: valid global/regular layout; rejected 3 malformed layouts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
