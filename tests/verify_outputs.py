#!/usr/bin/env python3
"""Integration test for the DATASE read-only probe; uses only the Python stdlib."""
from __future__ import annotations

import csv
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile


def read_csv(path: pathlib.Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def as_int(value: str) -> int:
    return int(value.strip('"'), 16) if value.startswith('0x') or value.startswith('"0x') else int(value)


def run_probe(exe: pathlib.Path, bin_dir: pathlib.Path, out_dir: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(exe), str(bin_dir), str(out_dir)], check=False, text=True, capture_output=True)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: verify_outputs.py <executable> <DATASE/BIN directory>", file=sys.stderr)
        return 2
    exe = pathlib.Path(sys.argv[1])
    bin_dir = pathlib.Path(sys.argv[2])
    wordseve_bytes = (bin_dir / "WORDSEVE.BIN").read_bytes()
    words_bytes = (bin_dir / "WORDS.BIN").read_bytes()

    with tempfile.TemporaryDirectory(prefix="datase_probe_test_") as temp:
        root = pathlib.Path(temp)
        output_dir = root / "out"
        run = run_probe(exe, bin_dir, output_dir)
        if run.returncode != 0:
            print(run.stdout, end="")
            print(run.stderr, end="", file=sys.stderr)
            raise AssertionError(f"probe exited with code {run.returncode}")

        # Verify the hypothesized two-block chain against the actual first words and target headers.
        assert struct.unpack_from("<I", words_bytes, 0)[0] == 0x91AC
        assert struct.unpack_from("<I", words_bytes, 0x91AC)[0] == 0
        assert struct.unpack_from("<I", wordseve_bytes, 0)[0] == 0x4280
        assert struct.unpack_from("<I", wordseve_bytes, 0x4280)[0] == 0
        blocks = read_csv(output_dir / "block_chain.csv")
        assert len(blocks) == 4
        indexed = {(row["file"].strip('"'), int(row["block_index"])): row for row in blocks}
        assert as_int(indexed[("WORDS.BIN", 0)]["first_word_pointer_candidate_hex"]) == 0x91AC
        assert as_int(indexed[("WORDS.BIN", 1)]["block_base_hex"]) == 0x91AC
        assert as_int(indexed[("WORDSEVE.BIN", 0)]["first_word_pointer_candidate_hex"]) == 0x4280
        assert as_int(indexed[("WORDSEVE.BIN", 1)]["block_base_hex"]) == 0x4280

        # The first WORDSEVE block's 68 entries all resolve to printable NUL-terminated ASCII strings.
        wordseve_rows = read_csv(output_dir / "WORDSEVE_offsets.csv")
        assert len(wordseve_rows) == 68, f"expected 68 WORDSEVE string rows, got {len(wordseve_rows)}"
        assert wordseve_rows[0]["relative_offset_hex"] == "0x0000"
        assert wordseve_rows[0]["string"] == "(I was asked to take somebody to the"
        assert wordseve_rows[1]["string"] == "Excuse me!"
        rels = [as_int(row["relative_offset_hex"]) for row in wordseve_rows]
        absolute = [as_int(row["absolute_offset_hex"]) for row in wordseve_rows]
        assert len(set(rels)) == 66, f"expected 66 unique offsets, got {len(set(rels))}"
        assert all(target == 0x4CC + rel for target, rel in zip(absolute, rels))
        for row, rel, target in zip(wordseve_rows, rels, absolute):
            assert target < len(wordseve_bytes)
            end = wordseve_bytes.find(b"\0", target)
            assert end >= target, f"no NUL terminator for offset {rel:#x}"
            assert wordseve_bytes[target:end].decode("ascii") == row["string"]

        # The second WORDSEVE block's 14 values are exported raw and are not mislabelled as string offsets.
        raw_eve = read_csv(output_dir / "WORDSEVE_tables_raw_u16.csv")
        assert len(raw_eve) == 82
        raw_eve_b0 = [row for row in raw_eve if int(row["block_index"]) == 0]
        raw_eve_b1 = [row for row in raw_eve if int(row["block_index"]) == 1]
        assert len(raw_eve_b0) == 68 and len(raw_eve_b1) == 14
        vals_b1 = [as_int(row["value_hex"]) for row in raw_eve_b1]
        assert vals_b1 == [1, 11, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]

        # WORDS has two raw regions; compare each value with the corresponding source bytes.
        raw_words = read_csv(output_dir / "WORDS_u16_region.csv")
        assert len(raw_words) == 448
        raw_words_b0 = [row for row in raw_words if int(row["block_index"]) == 0]
        raw_words_b1 = [row for row in raw_words if int(row["block_index"]) == 1]
        assert len(raw_words_b0) == 224 and len(raw_words_b1) == 224
        vals_b0 = [as_int(row["value_hex"]) for row in raw_words_b0]
        vals_b1 = [as_int(row["value_hex"]) for row in raw_words_b1]
        assert vals_b0[:3] == [0, 221, 0]
        assert vals_b1[:3] == [1, 221, 0]
        assert [as_int(row["source_offset_hex"]) for row in raw_words_b0] == list(range(0x338, 0x4F8, 2))
        assert [as_int(row["source_offset_hex"]) for row in raw_words_b1] == list(range(0x91AC + 0x338, 0x91AC + 0x4F8, 2))
        assert all(struct.unpack_from("<H", words_bytes, as_int(row["source_offset_hex"]))[0] == as_int(row["value_hex"])
                   for row in raw_words)
        differing = [i for i, (left, right) in enumerate(zip(vals_b0, vals_b1)) if left != right]
        assert differing == [0, *range(108, 224)], f"unexpected WORDS table diff positions: {differing}"

        report = (output_dir / "probe_report.txt").read_text(encoding="utf-8")
        assert "68/68" in report
        assert "linked-block chain" in report
        assert "arti tabel uint16 dan 6 byte preamble belum diketahui" in report

        # Negative test 1: malformed WORDSEVE table-end candidate must be rejected.
        bad_dir = root / "bad-wordseve"
        bad_dir.mkdir()
        shutil.copy2(bin_dir / "WORDS.BIN", bad_dir / "WORDS.BIN")
        bad_wordseve = bytearray(wordseve_bytes)
        bad_wordseve[0x20:0x24] = (0x100).to_bytes(4, "little")
        (bad_dir / "WORDSEVE.BIN").write_bytes(bad_wordseve)
        bad_run = run_probe(exe, bad_dir, root / "bad-wordseve-out")
        assert bad_run.returncode != 0, "malformed WORDSEVE table-end candidate was not rejected"
        assert "ERROR:" in bad_run.stderr

        # Negative test 2: pointer outside the file must be rejected before any table is emitted.
        bad_dir2 = root / "bad-words-pointer"
        bad_dir2.mkdir()
        bad_words = bytearray(words_bytes)
        bad_words[0:4] = (0xFFFFFFF0).to_bytes(4, "little")
        (bad_dir2 / "WORDS.BIN").write_bytes(bad_words)
        shutil.copy2(bin_dir / "WORDSEVE.BIN", bad_dir2 / "WORDSEVE.BIN")
        bad_run2 = run_probe(exe, bad_dir2, root / "bad-words-pointer-out")
        assert bad_run2.returncode != 0, "out-of-range WORDS block pointer was not rejected"
        assert "ERROR:" in bad_run2.stderr

    print("PASS: dua kandidat blok untuk setiap file cocok dengan pointer dan header pada byte sumber.")
    print("PASS: 68 string-offset WORDSEVE tervalidasi; tabel kandidat blok kedua disimpan mentah.")
    print("PASS: 448 nilai WORDS dibandingkan ulang dengan byte sumber pada kedua blok.")
    print("PASS: dua sampel rusak (end-table invalid dan block pointer out-of-range) ditolak dengan error.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
