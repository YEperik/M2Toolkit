#!/usr/bin/env python3
"""Synthetic tests for the read-only VIF vertex-batch scanner."""
from __future__ import annotations

import importlib.util
import pathlib
import struct
import sys


def load_module(path: pathlib.Path):
    spec = importlib.util.spec_from_file_location("scan_vertex_batches", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_tag(command: int, num: int, immediate: int) -> bytes:
    fmt = command & 0x0F
    components = {0x0: 1, 0x1: 1, 0x2: 1, 0x4: 2, 0x5: 2, 0x6: 2,
                  0x8: 3, 0x9: 3, 0xA: 3, 0xC: 4, 0xD: 4, 0xE: 4}[fmt]
    bits = {0x0: 32, 0x4: 32, 0x8: 32, 0xC: 32, 0x1: 16, 0x5: 16,
            0x9: 16, 0xD: 16, 0x2: 8, 0x6: 8, 0xA: 8, 0xE: 8}[fmt]
    qwc = (num * components * bits + 127) // 128
    vif1 = (command << 24) | ((num & 0xFF) << 16) | immediate
    return struct.pack("<4I", 0x10000000 | qwc, 0, 0, vif1) + bytes(qwc * 16)


def fixture_a() -> bytes:
    return b"".join([
        make_tag(0x6C, 2, 0x8000),
        make_tag(0x6D, 4, 0x8002),
        make_tag(0x6D, 4, 0x8003),
        make_tag(0x6E, 4, 0xC004),
        make_tag(0x74, 4, 0x8005),
    ])


def fixture_b() -> bytes:
    return b"".join([
        make_tag(0x6C, 3, 0x8000),
        make_tag(0x6D, 4, 0x8003),
        make_tag(0x6D, 4, 0x8004),
        make_tag(0x74, 4, 0x8005),
    ])


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: test_vertex_batch_scanner.py <scan_vertex_batches.py>", file=sys.stderr)
        return 2
    tool = pathlib.Path(sys.argv[1])
    scanner = load_module(tool)

    a = scanner.find_vertex_batches(fixture_a(), 0, "fixture_a.bin")
    assert len(a) == 1, a
    assert a[0]["layout_variant"] == "A_with_6E"
    assert a[0]["batch_start_hex"] == "0x0"
    assert a[0]["stream_a_num"] == a[0]["stream_b_num"] == a[0]["stream_74_num"] == 4
    assert a[0]["all_recognized_qwc_valid"] is True

    b = scanner.find_vertex_batches(fixture_b(), 1, "fixture_b.bin")
    assert len(b) == 1, b
    assert b[0]["layout_variant"] == "B_without_6E"
    assert b[0]["stream_a_num"] == b[0]["stream_b_num"] == b[0]["stream_74_num"] == 4

    broken = bytearray(fixture_a())
    original_word0 = struct.unpack_from("<I", broken, 0)[0]
    struct.pack_into("<I", broken, 0, (original_word0 & 0xFFFF0000) | 1)
    bad = scanner.find_vertex_batches(bytes(broken), 2, "broken.bin")
    assert bad == [], bad

    mismatch = b"".join([
        make_tag(0x6C, 2, 0x8000),
        make_tag(0x6D, 4, 0x8002),
        make_tag(0x6D, 3, 0x8003),
        make_tag(0x6E, 4, 0xC004),
        make_tag(0x74, 4, 0x8005),
    ])
    assert scanner.find_vertex_batches(mismatch, 3, "mismatch.bin") == []

    print("PASS: layout A detected with exact UNPACK QWC checks.")
    print("PASS: layout B detected with exact UNPACK QWC checks.")
    print("PASS: malformed QWC and mismatched core stream counts rejected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
