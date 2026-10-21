#!/usr/bin/env python3
"""Read-only extractor for an explicitly supplied linear PS2 DMA/VIF chain.

This is an exploratory tool, not a general PS2 DMAC interpreter. It supports
CNT tags (ID=1), a terminating RET tag (ID=6, QWC=0), and validates selected
VIF1 UNPACK formats before extracting their input payload bytes unchanged.
"""
from __future__ import annotations

import argparse
import csv
import pathlib
import struct
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class Tag:
    index: int
    offset: int
    word0: int
    word1: int
    vif0: int
    vif1: int
    dma_id: int
    qwc: int
    payload_offset: int
    payload_size: int
    vif_cmd: int
    vif_num: int
    vif_imm: int
    unpack_components: int | None
    unpack_bits: int | None
    expected_qwc: int | None


# UNPACK command's low nibble identifies components and source bit width.
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


def decode_unpack(cmd: int, num_field: int) -> tuple[int, int, int, int] | None:
    """Return (decoded_num, components, bits/component, expected_qwc).

    Format V4-5 (low nibble 0xF) is intentionally excluded because its input
    packing differs from the straightforward component-width formula.
    """
    if not 0x60 <= cmd <= 0x7F:
        return None
    fmt = cmd & 0x0F
    components = _COMPONENTS.get(fmt)
    bits = _BITS.get(fmt)
    if components is None or bits is None:
        return None
    decoded_num = num_field or 256
    total_bits = decoded_num * components * bits
    expected_qwc = (total_bits + 127) // 128
    return decoded_num, components, bits, expected_qwc


def trace_chain(data: bytes, start: int, max_tags: int = 2_000_000) -> list[Tag]:
    if start < 0 or start % 16 != 0 or start + 16 > len(data):
        raise ValueError("start offset must be 16-byte aligned and inside the input")

    tags: list[Tag] = []
    offset = start
    for index in range(max_tags):
        if offset + 16 > len(data):
            raise ValueError(f"DMA tag at 0x{offset:X} exceeds file bounds")
        word0, word1, vif0, vif1 = struct.unpack_from("<4I", data, offset)
        dma_id = (word0 >> 28) & 0x7
        qwc = word0 & 0xFFFF
        payload_offset = offset + 16
        payload_size = qwc * 16
        vif_cmd = (vif1 >> 24) & 0x7F
        num_field = (vif1 >> 16) & 0xFF
        vif_imm = vif1 & 0xFFFF
        unpack = decode_unpack(vif_cmd, num_field)
        components = bits = expected_qwc = None
        decoded_num = num_field
        if unpack is not None:
            decoded_num, components, bits, expected_qwc = unpack
            if expected_qwc != qwc:
                raise ValueError(
                    f"UNPACK QWC mismatch at 0x{offset:X}: tag QWC={qwc}, "
                    f"calculated QWC={expected_qwc}, VIF1=0x{vif1:08X}"
                )
        if payload_offset + payload_size > len(data):
            raise ValueError(f"payload at 0x{payload_offset:X} exceeds file bounds")

        tag = Tag(
            index=index, offset=offset, word0=word0, word1=word1,
            vif0=vif0, vif1=vif1, dma_id=dma_id, qwc=qwc,
            payload_offset=payload_offset, payload_size=payload_size,
            vif_cmd=vif_cmd, vif_num=decoded_num, vif_imm=vif_imm,
            unpack_components=components, unpack_bits=bits,
            expected_qwc=expected_qwc,
        )
        tags.append(tag)

        if dma_id == 6:  # RET
            if qwc != 0:
                raise ValueError(f"RET tag at 0x{offset:X} has nonzero QWC={qwc}")
            return tags
        if dma_id != 1:  # CNT only; other tag kinds need address/stack handling
            raise ValueError(
                f"unsupported DMA ID {dma_id} at 0x{offset:X}; tool supports only CNT and terminating RET"
            )
        offset = payload_offset + payload_size

    raise ValueError(f"chain did not terminate within {max_tags} tags")


def write_outputs(data: bytes, tags: list[Tag], input_path: pathlib.Path,
                  start: int, output_dir: pathlib.Path, label: str) -> None:
    if output_dir.exists():
        if not output_dir.is_dir() or any(output_dir.iterdir()):
            raise ValueError("output directory must not exist or must be empty")
    # All validation happened before output creation.
    output_dir.mkdir(parents=True, exist_ok=True)
    payload_dir = output_dir / "unpack_payloads"
    payload_dir.mkdir()

    tag_rows: list[dict[str, object]] = []
    unpack_rows: list[dict[str, object]] = []
    unpack_index = 0
    for tag in tags:
        tag_rows.append({
            "tag_index": tag.index,
            "tag_offset_hex": f"0x{tag.offset:X}",
            "dma_id": tag.dma_id,
            "dma_id_name": "CNT" if tag.dma_id == 1 else "RET",
            "qwc": tag.qwc,
            "word0_hex": f"0x{tag.word0:08X}",
            "word1_raw_hex": f"0x{tag.word1:08X}",
            "vif0_raw_hex": f"0x{tag.vif0:08X}",
            "vif1_raw_hex": f"0x{tag.vif1:08X}",
            "vif1_cmd_hex": f"0x{tag.vif_cmd:02X}",
            "vif1_num_decoded": tag.vif_num,
            "vif1_imm_hex": f"0x{tag.vif_imm:04X}",
            "payload_offset_hex": f"0x{tag.payload_offset:X}",
            "payload_size_bytes": tag.payload_size,
            "recognized_unpack": tag.unpack_components is not None,
        })
        if tag.unpack_components is None:
            continue
        filename = f"unpack_{unpack_index:04d}_tag_{tag.offset:08X}_cmd_{tag.vif_cmd:02X}_num_{tag.vif_num}.bin"
        payload = data[tag.payload_offset:tag.payload_offset + tag.payload_size]
        # Every payload remains an exact copy of source bytes.
        (payload_dir / filename).write_bytes(payload)
        unpack_rows.append({
            "unpack_index": unpack_index,
            "tag_index": tag.index,
            "tag_offset_hex": f"0x{tag.offset:X}",
            "payload_offset_hex": f"0x{tag.payload_offset:X}",
            "payload_size_bytes": tag.payload_size,
            "vif_cmd_hex": f"0x{tag.vif_cmd:02X}",
            "format": {0x6C: "V4-32", 0x6D: "V4-16", 0x6E: "V4-8", 0x74: "V2-32 (mask flag)"}.get(tag.vif_cmd, "UNPACK"),
            "num": tag.vif_num,
            "components": tag.unpack_components,
            "bits_per_component": tag.unpack_bits,
            "vif_imm_raw_hex": f"0x{tag.vif_imm:04X}",
            "expected_qwc": tag.expected_qwc,
            "qwc_matches": tag.expected_qwc == tag.qwc,
            "payload_file": filename,
        })
        unpack_index += 1

    def save_csv(path: pathlib.Path, rows: list[dict[str, object]]) -> None:
        if not rows:
            path.write_text("", encoding="utf-8")
            return
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    save_csv(output_dir / "chain_tags.csv", tag_rows)
    save_csv(output_dir / "unpack_payloads.csv", unpack_rows)
    cnt_count = sum(t.dma_id == 1 for t in tags)
    ret_count = sum(t.dma_id == 6 for t in tags)
    qwc_ok = all(r["qwc_matches"] for r in unpack_rows)
    source_hash_note = (
        "All extracted payloads are copied byte-for-byte from the specified input file; "
        "the input is opened read-only."
    )
    report = [
        "PS2 Part B linear DMA/VIF chain probe (exploratory)",
        "====================================================",
        f"Input: {input_path.name}",
        f"Label: {label}",
        f"Input size: {len(data)} bytes",
        f"Chain start: 0x{start:X}",
        f"Tag count: {len(tags)} ({cnt_count} CNT + {ret_count} RET)",
        f"Recognized VIF1 UNPACK payloads: {len(unpack_rows)}",
        f"All recognized UNPACK QWC values match calculated packed input sizes: {qwc_ok}",
        f"Extracted raw UNPACK bytes: {sum(int(r['payload_size_bytes']) for r in unpack_rows)}",
        "",
        "Recognized input layouts are limited to V4-32, V4-16, V4-8 and V2-32 (masked).",
        "This is raw VIF input data, not a decoded mesh: vertex semantics, VU microprogram,",
        "index/primitive layout, transforms and model-to-texture links remain unproven.",
        source_hash_note,
    ]
    (output_dir / "chain_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=pathlib.Path, help="raw Part B binary file")
    parser.add_argument("start_offset", help="chain start offset, e.g. 0x5A0")
    parser.add_argument("output_dir", type=pathlib.Path, help="new or empty output directory")
    parser.add_argument("--label", default="candidate", help="descriptive label for reports")
    args = parser.parse_args()
    try:
        start = int(args.start_offset, 0)
        data = args.input.read_bytes()
        tags = trace_chain(data, start)
        write_outputs(data, tags, args.input, start, args.output_dir, args.label)
    except (OSError, ValueError, struct.error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        f"PASS: traced {len(tags)} tags, extracted "
        f"{sum(t.unpack_components is not None for t in tags)} VIF UNPACK payloads to {args.output_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
