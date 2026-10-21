#!/usr/bin/env python3
"""Scan extracted PACKAGE.BIN Part B samples for repeated VIF1 UNPACK batches.

This is an exploratory, read-only scanner. It detects a small number of exact
command layouts and validates each recognized tag's QWC before reporting a
candidate. It does not assign model semantics or reconstruct triangle topology.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import math
import pathlib
import struct
import sys
from collections import Counter

MAX_PART_BYTES = 128 * 1024 * 1024

_COMPONENTS = {
    0x0: 1, 0x1: 1, 0x2: 1,
    0x4: 2, 0x5: 2, 0x6: 2,
    0x8: 3, 0x9: 3, 0xA: 3,
    0xC: 4, 0xD: 4, 0xE: 4,
}
_BITS = {
    0x0: 32, 0x4: 32, 0x8: 32, 0xC: 32,
    0x1: 16, 0x5: 16, 0x9: 16, 0xD: 16,
    0x2: 8, 0x6: 8, 0xA: 8, 0xE: 8,
}


def decode_unpack_tag(data: bytes, offset: int) -> dict[str, int | bool] | None:
    """Decode the subset of a 16-byte CNT/UNPACK tag needed by this scanner."""
    if offset < 0 or offset % 16 != 0 or offset + 16 > len(data):
        return None
    word0, _word1, _vif0, vif1 = struct.unpack_from("<4I", data, offset)
    dma_id = (word0 >> 28) & 0x7
    qwc = word0 & 0xFFFF
    command = (vif1 >> 24) & 0x7F
    num_field = (vif1 >> 16) & 0xFF
    num = num_field or 256
    immediate = vif1 & 0xFFFF
    fmt = command & 0x0F
    if not (0x60 <= command <= 0x7F and fmt in _COMPONENTS and fmt in _BITS):
        return None
    input_bits = num * _COMPONENTS[fmt] * _BITS[fmt]
    expected_qwc = (input_bits + 127) // 128
    return {
        "dma_id": dma_id,
        "qwc": qwc,
        "command": command,
        "num": num,
        "immediate": immediate,
        "expected_qwc": expected_qwc,
        "qwc_matches": qwc == expected_qwc,
    }


def _tag_at(data: bytes, offset: int, command: int, immediate: int) -> dict[str, int | bool] | None:
    tag = decode_unpack_tag(data, offset)
    if tag is None:
        return None
    if tag["dma_id"] != 1 or tag["command"] != command or tag["immediate"] != immediate:
        return None
    if not tag["qwc_matches"]:
        return None
    if offset + 16 + int(tag["qwc"]) * 16 > len(data):
        return None
    return tag


def find_vertex_batches(data: bytes, chunk_index: int, filename: str) -> list[dict[str, object]]:
    """Find exact, QWC-consistent repeated attribute-transfer patterns.

    Layout A: 6C/8000, 6D/8002, 6D/8003, optional 6E/C004, 74/8005.
    Layout B: 6C/8000, 6D/8003, 6D/8004, 74/8005.

    The words "position", "normal", "colour", and "UV" are intentionally
    avoided in the catalog because those meanings are not yet confirmed.
    """
    if len(data) > MAX_PART_BYTES:
        raise ValueError(f"{filename}: exceeds safe per-part limit of {MAX_PART_BYTES} bytes")
    rows: list[dict[str, object]] = []

    for start in range(0, len(data) - 15, 16):
        first = _tag_at(data, start, 0x6C, 0x8000)
        if first is None:
            continue
        offset_a = start + 16 + int(first["qwc"]) * 16
        tag_a = _tag_at(data, offset_a, 0x6D, 0x8002)
        tag_b_offset: int
        tag_b: dict[str, int | bool] | None
        colour_offset = -1
        colour_tag: dict[str, int | bool] | None = None
        uv_offset: int
        uv_tag: dict[str, int | bool] | None
        variant: str

        if tag_a is not None:
            offset_b = offset_a + 16 + int(tag_a["qwc"]) * 16
            tag_b = _tag_at(data, offset_b, 0x6D, 0x8003)
            if tag_b is None or tag_a["num"] != tag_b["num"]:
                continue
            after_b = offset_b + 16 + int(tag_b["qwc"]) * 16
            maybe_colour = _tag_at(data, after_b, 0x6E, 0xC004)
            if maybe_colour is not None:
                after_colour = after_b + 16 + int(maybe_colour["qwc"]) * 16
                possible_uv = _tag_at(data, after_colour, 0x74, 0x8005)
                if possible_uv is None or possible_uv["num"] != tag_a["num"]:
                    continue
                colour_offset = after_b
                colour_tag = maybe_colour
                uv_offset = after_colour
                uv_tag = possible_uv
                variant = "A_with_6E"
            else:
                possible_uv = _tag_at(data, after_b, 0x74, 0x8005)
                if possible_uv is None or possible_uv["num"] != tag_a["num"]:
                    continue
                uv_offset = after_b
                uv_tag = possible_uv
                variant = "A_without_6E"
            stream_a_offset = offset_a
            stream_b_offset = offset_b
        else:
            # A second observed layout writes the two V4-16 streams to 0x8003/0x8004.
            tag_a = _tag_at(data, offset_a, 0x6D, 0x8003)
            if tag_a is None:
                continue
            offset_b = offset_a + 16 + int(tag_a["qwc"]) * 16
            tag_b = _tag_at(data, offset_b, 0x6D, 0x8004)
            if tag_b is None or tag_a["num"] != tag_b["num"]:
                continue
            uv_offset = offset_b + 16 + int(tag_b["qwc"]) * 16
            uv_tag = _tag_at(data, uv_offset, 0x74, 0x8005)
            if uv_tag is None or uv_tag["num"] != tag_a["num"]:
                continue
            stream_a_offset = offset_a
            stream_b_offset = offset_b
            variant = "B_without_6E"

        batch_end = uv_offset + 16 + int(uv_tag["qwc"]) * 16
        if batch_end > len(data):
            continue
        # All four/five recognized tag QWCs have already been checked; also
        # assert the core stream counts align before publishing the row.
        rows.append({
            "chunk_index": chunk_index,
            "part_b_file": filename,
            "batch_start_hex": f"0x{start:X}",
            "layout_variant": variant,
            "control_num": int(first["num"]),
            "control_qwc": int(first["qwc"]),
            "stream_a_offset_hex": f"0x{stream_a_offset:X}",
            "stream_a_num": int(tag_a["num"]),
            "stream_a_qwc": int(tag_a["qwc"]),
            "stream_b_offset_hex": f"0x{stream_b_offset:X}",
            "stream_b_num": int(tag_b["num"]),
            "stream_b_qwc": int(tag_b["qwc"]),
            "stream_6e_offset_hex": "" if colour_offset < 0 else f"0x{colour_offset:X}",
            "stream_6e_num": "" if colour_tag is None else int(colour_tag["num"]),
            "stream_6e_qwc": "" if colour_tag is None else int(colour_tag["qwc"]),
            "stream_74_offset_hex": f"0x{uv_offset:X}",
            "stream_74_num": int(uv_tag["num"]),
            "stream_74_qwc": int(uv_tag["qwc"]),
            "batch_end_hex": f"0x{batch_end:X}",
            "core_counts_match": int(tag_a["num"]) == int(tag_b["num"]) == int(uv_tag["num"]),
            "all_recognized_qwc_valid": True,
        })
    return rows


def export_candidate_cloud(data: bytes, row: dict[str, object], out_dir: pathlib.Path) -> None:
    """Export one layout-A batch as raw CSV and a no-face PLY point cloud.

    The field interpretation is explicitly provisional: stream 0x8002 is used
    as point xyz, stream 0x8003 as normal-like xyz, 0xC004 as RGBA-like bytes,
    and 0x8005 as float-pair-like values. No face/index topology is inferred.
    """
    if row["layout_variant"] != "A_with_6E":
        raise ValueError("point-cloud export currently supports only layout A with the 0xC004 stream")
    if not row["core_counts_match"] or row["stream_6e_num"] != row["stream_a_num"]:
        raise ValueError("attribute counts are not aligned for a point-cloud export")

    stream_a = int(str(row["stream_a_offset_hex"]), 16)
    stream_b = int(str(row["stream_b_offset_hex"]), 16)
    stream_c = int(str(row["stream_6e_offset_hex"]), 16)
    stream_uv = int(str(row["stream_74_offset_hex"]), 16)
    count = int(row["stream_a_num"])
    pos_bytes = data[stream_a + 16:stream_a + 16 + int(row["stream_a_qwc"]) * 16]
    nrm_bytes = data[stream_b + 16:stream_b + 16 + int(row["stream_b_qwc"]) * 16]
    col_bytes = data[stream_c + 16:stream_c + 16 + int(row["stream_6e_qwc"]) * 16]
    uv_bytes = data[stream_uv + 16:stream_uv + 16 + int(row["stream_74_qwc"]) * 16]
    if len(pos_bytes) != count * 8 or len(nrm_bytes) != count * 8:
        raise ValueError("V4-16 payload byte count is not exact for the advertised count")
    if len(col_bytes) < count * 4 or len(uv_bytes) != count * 8:
        raise ValueError("colour-like or float-pair payload byte count does not fit the count")

    values: list[dict[str, object]] = []
    positions: list[tuple[float, float, float]] = []
    normals: list[tuple[float, float, float]] = []
    colours: list[tuple[int, int, int, int]] = []
    uvs: list[tuple[float, float]] = []
    for i in range(count):
        a = struct.unpack_from("<4h", pos_bytes, i * 8)
        b = struct.unpack_from("<4h", nrm_bytes, i * 8)
        col = tuple(col_bytes[i * 4:i * 4 + 4])
        uv = struct.unpack_from("<2f", uv_bytes, i * 8)
        if not all(math.isfinite(v) for v in uv):
            raise ValueError(f"non-finite float pair in item {i}")
        pos = (a[0] / 4096.0, a[1] / 4096.0, a[2] / 4096.0)
        nrm = (b[0] / 4096.0, b[1] / 4096.0, b[2] / 4096.0)
        colours4 = (int(col[0]), int(col[1]), int(col[2]), int(col[3]))
        positions.append(pos)
        normals.append(nrm)
        colours.append(colours4)
        uvs.append((float(uv[0]), float(uv[1])))
        values.append({
            "item_index": i,
            "stream_8002_s16_0": a[0], "stream_8002_s16_1": a[1],
            "stream_8002_s16_2": a[2], "stream_8002_s16_3": a[3],
            "stream_8003_s16_0": b[0], "stream_8003_s16_1": b[1],
            "stream_8003_s16_2": b[2], "stream_8003_s16_3": b[3],
            "stream_c004_u8_0": colours4[0], "stream_c004_u8_1": colours4[1],
            "stream_c004_u8_2": colours4[2], "stream_c004_u8_3": colours4[3],
            "stream_8005_f32_0": uv[0], "stream_8005_f32_1": uv[1],
            "candidate_x_scale4096": pos[0], "candidate_y_scale4096": pos[1],
            "candidate_z_scale4096": pos[2],
            "candidate_nx_scale4096": nrm[0], "candidate_ny_scale4096": nrm[1],
            "candidate_nz_scale4096": nrm[2],
        })

    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "candidate_batch_raw_join.csv"
    if csv_path.exists():
        raise ValueError(f"refusing to overwrite {csv_path}")
    with csv_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(values[0].keys()))
        writer.writeheader()
        writer.writerows(values)

    ply_path = out_dir / "candidate_vertex_cloud_scale4096.ply"
    with ply_path.open("x", encoding="ascii", newline="\n") as file:
        file.write("ply\nformat ascii 1.0\n")
        file.write(f"comment source {row['part_b_file']}\n")
        file.write(f"comment source_batch_start {row['batch_start_hex']}\n")
        file.write("comment xyz=stream_8002 signed16 divided by 4096 (hypothesis)\n")
        file.write("comment normals=stream_8003 signed16 divided by 4096 (hypothesis)\n")
        file.write("comment rgba=stream_C004 bytes (hypothesis)\n")
        file.write("comment s_t=stream_8005 little-endian float pairs (hypothesis)\n")
        file.write("comment point cloud only; no faces/topology inferred\n")
        file.write(f"element vertex {count}\n")
        for name in ("x", "y", "z", "nx", "ny", "nz"):
            file.write(f"property float {name}\n")
        for name in ("red", "green", "blue", "alpha"):
            file.write(f"property uchar {name}\n")
        file.write("property float s\nproperty float t\nend_header\n")
        for i in range(count):
            fields = (*positions[i], *normals[i], *colours[i], *uvs[i])
            file.write(" ".join(str(v) for v in fields) + "\n")

    # Optional visual inspection aid; the machine-readable PLY and CSV do not
    # depend on matplotlib being installed.
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig = plt.figure(figsize=(8, 6))
        ax = fig.add_subplot(111, projection="3d")
        ax.scatter([p[0] for p in positions], [p[1] for p in positions], [p[2] for p in positions], s=18)
        ax.set_xlabel("stream 0x8002 X / 4096")
        ax.set_ylabel("stream 0x8002 Y / 4096")
        ax.set_zlabel("stream 0x8002 Z / 4096")
        ax.set_title(f"Candidate point cloud — {count} items; topology unknown")
        ranges = [max(v[i] for v in positions) - min(v[i] for v in positions) for i in range(3)]
        max_range = max(ranges) or 1.0
        mid = [
            (max(v[i] for v in positions) + min(v[i] for v in positions)) / 2.0
            for i in range(3)
        ]
        ax.set_xlim(mid[0] - max_range / 2, mid[0] + max_range / 2)
        ax.set_ylim(mid[1] - max_range / 2, mid[1] + max_range / 2)
        ax.set_zlim(mid[2] - max_range / 2, mid[2] + max_range / 2)
        fig.tight_layout()
        fig.savefig(out_dir / "candidate_vertex_cloud_preview.png", dpi=150)
        plt.close(fig)
    except ImportError:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("part_b_directory", type=pathlib.Path,
                        help="directory containing chunk_NN_part_b.bin files")
    parser.add_argument("output_directory", type=pathlib.Path,
                        help="new or empty output directory")
    parser.add_argument("--export-cloud", metavar="CHUNK:OFFSET",
                        help="also export a provisional no-face cloud, e.g. 0:0x5A0")
    args = parser.parse_args()

    try:
        if not args.part_b_directory.is_dir():
            raise ValueError(f"not a directory: {args.part_b_directory}")
        output = args.output_directory
        if output.exists() and (not output.is_dir() or any(output.iterdir())):
            raise ValueError("output directory must not exist or must be empty")
        paths = sorted(args.part_b_directory.glob("chunk_*_part_b.bin"))
        if not paths:
            raise ValueError("no chunk_*_part_b.bin files found")

        all_rows: list[dict[str, object]] = []
        summaries: list[dict[str, object]] = []
        data_by_chunk: dict[int, bytes] = {}
        rows_by_chunk: dict[int, list[dict[str, object]]] = {}
        digest_by_chunk: dict[int, str] = {}
        for path in paths:
            try:
                chunk_index = int(path.name.split("_")[1])
            except (IndexError, ValueError) as exc:
                raise ValueError(f"unexpected Part B filename: {path.name}") from exc
            size = path.stat().st_size
            if size > MAX_PART_BYTES:
                raise ValueError(f"{path.name}: exceeds safe per-part limit")
            data = path.read_bytes()
            rows = find_vertex_batches(data, chunk_index, path.name)
            data_by_chunk[chunk_index] = data
            rows_by_chunk[chunk_index] = rows
            digest_by_chunk[chunk_index] = hashlib.sha256(data).hexdigest()
            all_rows.extend(rows)
            counts = Counter(str(row["layout_variant"]) for row in rows)
            summaries.append({
                "chunk_index": chunk_index,
                "part_b_file": path.name,
                "part_b_size_bytes": size,
                "sha256": digest_by_chunk[chunk_index],
                "candidate_batches": len(rows),
                "layout_A_with_6E": counts["A_with_6E"],
                "layout_A_without_6E": counts["A_without_6E"],
                "layout_B_without_6E": counts["B_without_6E"],
                "vertex_items_core_streams": sum(int(row["stream_a_num"]) for row in rows),
                "all_core_counts_match": all(bool(row["core_counts_match"]) for row in rows),
            })

        output.mkdir(parents=True, exist_ok=True)
        if all_rows:
            with (output / "vertex_batch_candidates.csv").open("w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=list(all_rows[0].keys()))
                writer.writeheader()
                writer.writerows(all_rows)
        else:
            (output / "vertex_batch_candidates.csv").write_text("", encoding="utf-8")
        with (output / "chunk_summary.csv").open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=list(summaries[0].keys()))
            writer.writeheader()
            writer.writerows(summaries)

        report_lines = [
            "DATASE Part B VIF batch scan (exploratory/read-only)",
            "====================================================",
            f"Part B files scanned: {len(paths)}",
            f"Candidate batches found: {len(all_rows)}",
            "Detection layouts: A = 6C/8000 + 6D/8002 + 6D/8003 + optional 6E/C004 + 74/8005;",
            "                   B = 6C/8000 + 6D/8003 + 6D/8004 + 74/8005.",
            "For every reported tag, the scanner checked CNT ID, command/immediate, bounds, and QWC formula.",
            "Core stream counts (the two V4-16 streams and the V2-32 stream) must agree.",
            "These are candidate attribute-transfer batches, not confirmed models or object counts.",
            "No triangle indices, face topology, material links, or semantic labels are inferred.",
            "",
            "Per-chunk summary:",
        ]
        for row in summaries:
            report_lines.append(
                f"  chunk {int(row['chunk_index']):02d}: {int(row['candidate_batches'])} candidates "
                f"(A+6E={int(row['layout_A_with_6E'])}, A-no-6E={int(row['layout_A_without_6E'])}, "
                f"B-no-6E={int(row['layout_B_without_6E'])}); SHA-256={row['sha256']}"
            )
        report_lines.extend([
            "",
            "Interpretation limits:",
            "- Exact repeated UNPACK patterns and QWC agreement support structured VIF payloads.",
            "- A candidate can still be a referenced/substructure record rather than an independent mesh.",
            "- Layout A stream labels and the /4096 coordinate normalization used by the optional cloud are hypotheses.",
            "- PLY output is point-only and deliberately contains no inferred faces.",
        ])
        (output / "scan_report.txt").write_text("\n".join(report_lines) + "\n", encoding="utf-8")

        if args.export_cloud:
            try:
                chunk_text, offset_text = args.export_cloud.split(":", 1)
                chunk_index = int(chunk_text, 0)
                offset = int(offset_text, 0)
            except ValueError as exc:
                raise ValueError("--export-cloud must use CHUNK:OFFSET, e.g. 0:0x5A0") from exc
            target = next((r for r in rows_by_chunk.get(chunk_index, [])
                           if int(str(r["batch_start_hex"]), 16) == offset), None)
            if target is None:
                raise ValueError(f"no validated candidate batch at chunk {chunk_index}, offset 0x{offset:X}")
            export_dir = output / "sample_cloud"
            export_candidate_cloud(data_by_chunk[chunk_index], target, export_dir)
            (export_dir / "sample_cloud_notes.txt").write_text(
                "This is a provisional point-cloud inspection export, not a recovered mesh.\n"
                f"Source: chunk_{chunk_index:02d}_part_b.bin\n"
                f"Batch start: 0x{offset:X}\n"
                f"Layout: {target['layout_variant']}\n"
                f"Item count on aligned core streams: {target['stream_a_num']}\n"
                "Field roles and /4096 fixed-point scale are hypotheses. There are no faces or indices.\n",
                encoding="utf-8",
            )

        total_by_layout = Counter(str(row["layout_variant"]) for row in all_rows)
        print(f"PASS: scanned {len(paths)} Part B files; found {len(all_rows)} candidate batches")
        print("Layouts: " + ", ".join(f"{k}={v}" for k, v in sorted(total_by_layout.items())))
        print(f"Output: {output}")
        return 0
    except (OSError, ValueError, struct.error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
