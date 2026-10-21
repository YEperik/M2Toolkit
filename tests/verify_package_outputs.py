#!/usr/bin/env python3
"""Integration tests for the read-only PACKAGE.BIN chunk splitter (stdlib only)."""
from __future__ import annotations

import csv
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile


def run_probe(exe: pathlib.Path, source: pathlib.Path, out: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(exe), str(source), str(out)], check=False, text=True, capture_output=True)


def read_csv(path: pathlib.Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: verify_package_outputs.py <executable> <PACKAGE.BIN>", file=sys.stderr)
        return 2
    exe = pathlib.Path(sys.argv[1])
    source = pathlib.Path(sys.argv[2])
    data = source.read_bytes()

    with tempfile.TemporaryDirectory(prefix="datase_package_probe_test_") as temp:
        root = pathlib.Path(temp)
        out = root / "valid-out"
        run = run_probe(exe, source, out)
        if run.returncode != 0:
            print(run.stdout, end="")
            print(run.stderr, end="", file=sys.stderr)
            raise AssertionError(f"valid PACKAGE.BIN rejected with exit code {run.returncode}")

        rows = read_csv(out / "package_catalog.csv")
        table_end = u32(data, 0)
        assert table_end == 0x320
        assert (table_end - 0x20) % 0x20 == 0
        assert len(rows) == (table_end - 0x20) // 0x20 == 24
        assert "24/24" in (out / "package_report.txt").read_text(encoding="utf-8")

        expected_start = None
        total_a = total_b = 0
        for i, row in enumerate(rows):
            desc = 0x20 + i * 0x20
            start = u32(data, desc)
            part_a = u32(data, desc + 4)
            part_b = u32(data, desc + 8)
            expected_next = u32(data, desc + 0x20) if i + 1 < len(rows) else len(data)
            assert int(row["index"]) == i
            assert int(row["chunk_start_hex"].strip('"'), 16) == start
            assert int(row["part_a_size_bytes"]) == part_a
            assert int(row["part_b_size_bytes"]) == part_b
            assert start + part_a + part_b == expected_next, (i, hex(start), hex(part_a), hex(part_b), hex(expected_next))
            if expected_start is not None:
                assert start == expected_start
            expected_start = expected_next
            total_a += part_a
            total_b += part_b

            stem = f"chunk_{i:02d}"
            part_a_path = out / f"{stem}_part_a.bin"
            part_b_path = out / f"{stem}_part_b.bin"
            assert part_a_path.stat().st_size == part_a
            assert part_b_path.stat().st_size == part_b
            assert part_a_path.read_bytes() == data[start:start + part_a]
            assert part_b_path.read_bytes() == data[start + part_a:start + part_a + part_b]

        assert expected_start == len(data)
        assert total_a + total_b == len(data) - u32(data, 0x20)

        # Validate the PS2 VIF/DMA/GIF image-transfer interpretation from the actual source bytes.
        uploads = read_csv(out / "texture_uploads.csv")
        assert len(uploads) == 2738
        assert all(row["dimensions_match"] == "true" for row in uploads)
        assert {row["psm_name"] for row in uploads} == {"PSMT4", "PSMT8", "PSMCT32"}
        assert sum(row["psm_name"] == "PSMT4" for row in uploads) == 2545
        assert sum(row["psm_name"] == "PSMT8" for row in uploads) == 2
        assert sum(row["psm_name"] == "PSMCT32" for row in uploads) == 191
        assert len(list((out / "texture_payloads").glob("*.bin"))) == 2738
        for row in uploads:
            payload = (out / "texture_payloads" / row["payload_file"]).read_bytes()
            source_offset = int(row["payload_offset_in_package_hex"].strip('"'), 16)
            payload_size = int(row["payload_size_bytes"])
            width = int(row["width"])
            height = int(row["height"])
            bpp = int(row["bits_per_pixel"])
            assert len(payload) == payload_size == int(row["expected_size_bytes"])
            assert source_offset + payload_size <= len(data)
            assert payload == data[source_offset:source_offset + payload_size]
            assert width * height * bpp // 8 == payload_size
            assert int(row["gif_image_nloop"]) * 16 == payload_size

        dma_tags = read_csv(out / "dma_chain_tags.csv")
        assert len(dma_tags) == 5500
        assert sum(row["id_name"] == "CNT" for row in dma_tags) == 5476
        assert sum(row["id_name"] == "RET" for row in dma_tags) == 24
        for row in dma_tags:
            if row["id_name"] == "RET":
                assert int(row["qwc"]) == 0
                assert int(row["payload_bytes"]) == 0

        # Fail closed if the purported descriptor-table end is not stride-aligned.
        bad_data = bytearray(data)
        bad_data[0:4] = (0x321).to_bytes(4, "little")
        bad_source = root / "bad-table-end.bin"
        bad_source.write_bytes(bad_data)
        bad = run_probe(exe, bad_source, root / "bad-out")
        assert bad.returncode != 0
        assert "ERROR:" in bad.stderr

        # Fail closed if a descriptor's parts do not reach the next chunk boundary.
        bad_data2 = bytearray(data)
        bad_data2[0x24:0x28] = (0x5F11).to_bytes(4, "little")
        bad_source2 = root / "bad-part-size.bin"
        bad_source2.write_bytes(bad_data2)
        bad2 = run_probe(exe, bad_source2, root / "bad-out2")
        assert bad2.returncode != 0
        assert "ERROR:" in bad2.stderr

        # Fail closed if a VIF DIRECT immediate no longer agrees with its QWC/image payload.
        bad_data3 = bytearray(data)
        first_chunk_start = u32(data, 0x20)
        # First setup tag is 0x70 bytes long; the data tag's VIF DIRECT lives at +0x0C.
        bad_data3[first_chunk_start + 0x7C:first_chunk_start + 0x80] = (0x50000007).to_bytes(4, "little")
        bad_source3 = root / "bad-vif-direct.bin"
        bad_source3.write_bytes(bad_data3)
        bad3 = run_probe(exe, bad_source3, root / "bad-out3")
        assert bad3.returncode != 0
        assert "ERROR:" in bad3.stderr
        assert not (root / "bad-out3").exists(), "Malformed chain should fail before output creation."

    print("PASS: 24 descriptor; semua batas A+B tepat ke start chunk berikutnya/EOF.")
    print("PASS: seluruh 48 potongan mentah identik byte-for-byte dengan sumber.")
    print("PASS: 2738 image transfer, semua ukuran pixel dan GIF QWC cocok, payload identik dengan sumber.")
    print("PASS: 5500 tag tercatat (5476 CNT + 24 RET), dan input chain yang dimodifikasi ditolak.")
    print("PASS: tabel descriptor rusak dan ukuran part yang salah ditolak.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
