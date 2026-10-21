#!/usr/bin/env python3
"""Integration validation for the real PACKAGE.BIN Stage 6 mapping output."""
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
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: verify_stage6_package_map.py PACKAGE.BIN candidates.csv map_package_assets.py", file=sys.stderr)
        return 2
    package = pathlib.Path(sys.argv[1])
    candidates = pathlib.Path(sys.argv[2])
    script = pathlib.Path(sys.argv[3])
    original_hash = sha256(package)
    with tempfile.TemporaryDirectory(prefix="datase_stage6_test_") as temp:
        out = pathlib.Path(temp) / "out"
        subprocess.run([sys.executable, str(script), str(package), str(candidates), str(out)], check=True)
        summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
        assert summary["package_sha256"] == original_hash
        assert summary["regular_descriptor_count"] == 24
        assert summary["total_descriptors_including_global"] == 25
        assert summary["global_part_a_texture_uploads"] == 27
        assert summary["global_texture_payload_bytes"] == 24576
        assert summary["part_b_candidate_batches_in_24_chunks"] == 11859
        assert summary["global_part_b_candidate_batches"] == 134
        assert summary["total_candidate_batches"] == 11993
        assert summary["descriptor_ranges_contiguous"] is True
        assert summary["candidate_batches_non_overlapping_by_part_b"] is True
        assert summary["model_topology_confirmed"] is False
        with (out / "global_part_b_candidates.csv").open("r", newline="", encoding="utf-8") as stream:
            global_rows = list(csv.DictReader(stream))
        assert len(global_rows) == 134
        assert all(int(row["chunk_index"]) == 24 for row in global_rows)
        with (out / "vif_batch_absolute_map.csv").open("r", newline="", encoding="utf-8") as stream:
            all_rows = list(csv.DictReader(stream))
        assert len(all_rows) == 11993
        assert sum(int(row["chunk_index"]) == 24 for row in all_rows) == 134
        assert (out / "texture_payloads").is_dir()
        assert len(list((out / "texture_payloads").glob("*.bin"))) == 27
    assert sha256(package) == original_hash, "PACKAGE.BIN changed during read-only analysis"
    print("PASS: real package boundaries, 27 global textures, 11,859 chunk batches, 134 global batches, source unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
