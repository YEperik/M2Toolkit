#!/usr/bin/env python3
"""Synthetic no-game-data tests for the exploratory VIF UNPACK chain reader."""
from __future__ import annotations

import pathlib
import struct
import subprocess
import sys
import tempfile


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: test_vif_unpack_tool.py <extract_vif_unpack_chain.py>", file=sys.stderr)
        return 2
    tool = pathlib.Path(sys.argv[1])
    # CNT QWC=2, VIF1=UNPACK V4-16 NUM=4 ADDR=0x8002, then 32 bytes.
    payload = bytes(range(32))
    tag = struct.pack("<4I", 0x10000002, 0, 0, 0x6D048002)
    ret = struct.pack("<4I", 0x60000000, 0, 0, 0)
    fixture = tag + payload + ret

    with tempfile.TemporaryDirectory(prefix="datase_vif_tool_test_") as temp:
        root = pathlib.Path(temp)
        source = root / "fixture.bin"
        source.write_bytes(fixture)
        output = root / "good-out"
        ok = subprocess.run(
            [sys.executable, str(tool), str(source), "0x0", str(output), "--label", "synthetic"],
            capture_output=True, text=True, check=False,
        )
        assert ok.returncode == 0, (ok.stdout, ok.stderr)
        report = (output / "chain_report.txt").read_text(encoding="utf-8")
        assert "Tag count: 2 (1 CNT + 1 RET)" in report
        assert "Recognized VIF1 UNPACK payloads: 1" in report
        extracted = list((output / "unpack_payloads").glob("*.bin"))
        assert len(extracted) == 1 and extracted[0].read_bytes() == payload

        # The wrong QWC must fail before creating output.
        broken = bytearray(fixture)
        broken[0:4] = (0x10000001).to_bytes(4, "little")
        bad_source = root / "bad.bin"
        bad_source.write_bytes(broken)
        bad_output = root / "bad-out"
        bad = subprocess.run(
            [sys.executable, str(tool), str(bad_source), "0x0", str(bad_output)],
            capture_output=True, text=True, check=False,
        )
        assert bad.returncode != 0
        assert "QWC mismatch" in bad.stderr
        assert not bad_output.exists()

    print("PASS: synthetic VIF UNPACK extraction preserves payload bytes exactly.")
    print("PASS: malformed QWC rejected before output creation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
