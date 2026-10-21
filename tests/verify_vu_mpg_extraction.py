#!/usr/bin/env python3
"""Integration test for observed VIF MPG records embedded in the supplied PS2 ELF."""
from __future__ import annotations
import csv
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: verify_vu_mpg_extraction.py ELF extract_script control_tags.csv", file=sys.stderr)
        return 2
    elf = pathlib.Path(sys.argv[1])
    script = pathlib.Path(sys.argv[2])
    controls = pathlib.Path(sys.argv[3])
    before = sha256(elf)
    with tempfile.TemporaryDirectory(prefix="datase_vu_mpg_test_") as temp:
        out = pathlib.Path(temp) / "vu_out"
        subprocess.run([sys.executable, str(script), str(elf), str(out), "--control-csv", str(controls)], check=True)
        summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
        assert summary["input_sha256"] == before
        assert summary["top_level_mpg_records"] == 20
        assert summary["embedded_mpg_records"] == 1
        assert summary["total_mpg_program_images_extracted"] == 21
        assert summary["all_top_level_records_contiguous_by_qwc"] is True
        assert summary["msc_cal_asset_candidate_counts"]["0x0000006C"] == 180
        assert summary["msc_cal_asset_candidate_counts"]["0x000000B8"] == 5559
        assert summary["msc_cal_asset_candidate_counts"]["0x000003A0"] == 503
        with (out / "vu_embedded_mpg_catalog.csv").open("r", newline="", encoding="utf-8") as stream:
            nested = list(csv.DictReader(stream))
        assert len(nested) == 1
        row = nested[0]
        assert int(row["destination"]) == 0x580
        assert int(row["instruction_count"]) == 35
        assert int(row["command_file_offset"]) == 0xBFE84
        assert (out / row["program_file"]).stat().st_size == 280
        with (out / "vu_microprogram_catalog.csv").open("r", newline="", encoding="utf-8") as stream:
            records = list(csv.DictReader(stream))
        assert len(records) == 20
        parent = next(r for r in records if int(r["dma_tag_file_offset_hex"], 16) == 0xBF670)
        assert int(parent["effective_instruction_count"]) == 256
        assert int(parent["trailing_bytes_after_declared_mpg"]) == 288
        assert sha256(elf) == before, "executable changed during read-only analysis"
    print("PASS: 20 top-level MPG records, 1 embedded MPG, MSCAL cross-refs, source unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
