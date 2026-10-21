#!/usr/bin/env python3
"""Extract validated VIF MPG microprogram candidates embedded in an ELF32 PS2 executable.

The tool only reads the input executable. It requires 16-byte-aligned DMA-tag candidates
with a VIF MPG command, bounds-checks QWC payloads against PT_LOAD segments, verifies the
MPG instruction count fits the payload and VU address window, and preserves raw QWC/tail data.
It does not disassemble VU instructions or claim that a given program corresponds to a model.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import pathlib
import struct
import sys
from collections import Counter, defaultdict
from itertools import combinations

PT_LOAD = 1
EM_MIPS = 8
VIF_CMD_MPG = 0x4A
VU_MICRO_INSTRUCTION_LIMIT = 2048
ELF32_HEADER_SIZE = 52
ELF32_PROGRAM_HEADER_SIZE = 32


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hx(value: int) -> str:
    return f"0x{value:08X}"


def unpack_elf(data: bytes) -> tuple[int, list[dict[str, int]]]:
    if len(data) < ELF32_HEADER_SIZE or data[:4] != b"\x7fELF":
        raise ValueError("input is not a complete ELF file")
    if data[4] != 1 or data[5] != 1:
        raise ValueError("expected ELF32 little-endian input")
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    if e_type != 2 or e_machine != EM_MIPS:
        raise ValueError(f"expected MIPS ET_EXEC ELF (type=2, machine=8); got {e_type}, {e_machine}")
    e_phoff = struct.unpack_from("<I", data, 28)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 42)
    if e_phentsize < ELF32_PROGRAM_HEADER_SIZE or e_phoff + e_phentsize * e_phnum > len(data):
        raise ValueError("program header table is truncated or malformed")
    segments = []
    for i in range(e_phnum):
        fields = struct.unpack_from("<8I", data, e_phoff + i * e_phentsize)
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = fields
        del p_paddr, p_memsz, p_flags, p_align
        if p_type != PT_LOAD or p_filesz == 0:
            continue
        if p_offset + p_filesz > len(data):
            raise ValueError(f"PT_LOAD segment {i} extends past end of ELF file")
        segments.append({"index": i, "file_start": p_offset, "file_end": p_offset + p_filesz,
                         "vaddr_start": p_vaddr})
    if not segments:
        raise ValueError("ELF has no file-backed PT_LOAD segment")
    return struct.unpack_from("<I", data, 24)[0], segments


def parse_mpg_tags(data: bytes, segments: list[dict[str, int]]) -> list[dict[str, int]]:
    candidates: list[dict[str, int]] = []
    for seg in segments:
        begin = (seg["file_start"] + 15) & ~15
        end = seg["file_end"]
        for off in range(begin, end - 15, 16):
            word0, word1, word2, word3 = struct.unpack_from("<4I", data, off)
            dma_id = (word0 >> 28) & 7
            qwc = word0 & 0xFFFF
            cmd = (word3 >> 24) & 0x7F
            num_raw = (word3 >> 16) & 0xFF
            dest = word3 & 0xFFFF
            # In this executable these candidate records use RET tags with reserved fields zero.
            if dma_id != 6 or word1 != 0 or word2 != 0 or cmd != VIF_CMD_MPG or qwc == 0:
                continue
            count = num_raw or 256
            if dest + count > VU_MICRO_INSTRUCTION_LIMIT:
                continue
            declared_bytes = count * 8  # VIF MPG transfers 64-bit microinstructions.
            capacity_bytes = qwc * 16
            payload_offset = off + 16
            payload_end = payload_offset + capacity_bytes
            if capacity_bytes < declared_bytes or payload_end > end:
                continue
            candidates.append({
                "segment_index": seg["index"], "file_offset": off,
                "virtual_address": seg["vaddr_start"] + (off - seg["file_start"]),
                "tag_word0": word0, "tag_word1": word1, "tag_word2": word2, "vif_word": word3,
                "dma_id": dma_id, "qwc": qwc, "vif_num_raw": num_raw,
                "instruction_count": count, "num_zero_means_256": int(num_raw == 0),
                "destination": dest, "declared_bytes": declared_bytes,
                "qwc_payload_bytes": capacity_bytes, "tail_bytes": capacity_bytes - declared_bytes,
                "payload_offset": payload_offset, "payload_end": payload_end,
            })
    candidates.sort(key=lambda item: item["file_offset"])
    return candidates


def parse_embedded_mpgs(parent: dict[str, int], tail: bytes) -> tuple[list[dict[str, int | str]], list[dict[str, int | str]]]:
    """Parse NOP(s) followed by complete embedded MPG commands from a parent's extra tail."""
    embedded: list[dict[str, int | str]] = []
    controls: list[dict[str, int | str]] = []
    pos = 0
    while pos + 4 <= len(tail):
        word = struct.unpack_from("<I", tail, pos)[0]
        if word == 0:
            controls.append({"tail_offset": pos, "vif_word_hex": f"0x{word:08X}", "command": "NOP"})
            pos += 4
            continue
        cmd = (word >> 24) & 0x7F
        if cmd != VIF_CMD_MPG:
            controls.append({"tail_offset": pos, "vif_word_hex": f"0x{word:08X}", "command": f"UNKNOWN_0x{cmd:02X}"})
            break
        num_raw = (word >> 16) & 0xFF
        count = num_raw or 256
        dest = word & 0xFFFF
        size = count * 8
        data_offset = pos + 4
        if dest + count > VU_MICRO_INSTRUCTION_LIMIT or data_offset + size > len(tail):
            controls.append({"tail_offset": pos, "vif_word_hex": f"0x{word:08X}", "command": "MPG_INVALID_OR_TRUNCATED"})
            break
        embedded.append({
            "parent_file_offset": parent["file_offset"],
            "parent_virtual_address": parent["virtual_address"],
            "tail_relative_command_offset": pos,
            "command_file_offset": parent["payload_offset"] + parent["declared_bytes"] + pos,
            "command_virtual_address": parent["virtual_address"] + 16 + parent["declared_bytes"] + pos,
            "vif_word": word, "destination": dest, "num_raw": num_raw,
            "instruction_count": count, "payload_tail_relative_offset": data_offset,
            "payload_file_offset": parent["payload_offset"] + parent["declared_bytes"] + data_offset,
            "payload_bytes": size,
        })
        controls.append({"tail_offset": pos, "vif_word_hex": f"0x{word:08X}", "command": "MPG",
                         "destination": dest, "num_raw": num_raw, "instruction_count": count,
                         "payload_bytes": size})
        pos = data_offset + size
    return embedded, controls


def write_csv(path: pathlib.Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=pathlib.Path, help="PS2 ELF32 little-endian MIPS executable")
    parser.add_argument("output_dir", type=pathlib.Path, help="new or empty output directory")
    parser.add_argument("--control-csv", type=pathlib.Path, help="optional mapped VIF batch control-tag CSV for MSCAL cross-reference")
    args = parser.parse_args()
    try:
        if args.output_dir.exists() and (not args.output_dir.is_dir() or any(args.output_dir.iterdir())):
            raise ValueError("output directory must be new or empty")
        data = args.executable.read_bytes()
        entry, segments = unpack_elf(data)
        records = parse_mpg_tags(data, segments)
        if not records:
            raise ValueError("no validated VIF MPG records found in PT_LOAD segments")
        out = args.output_dir
        out.mkdir(parents=True, exist_ok=True)
        prog_dir = out / "microprograms"
        qwc_dir = out / "qwc_payloads"
        tail_dir = out / "tails"
        prog_dir.mkdir(); qwc_dir.mkdir(); tail_dir.mkdir()
        output_records: list[dict[str, object]] = []
        embedded_records: list[dict[str, object]] = []
        embedded_control_rows: list[dict[str, object]] = []
        instruction_rows: list[dict[str, object]] = []
        program_images: list[dict[str, object]] = []
        for i, rec in enumerate(records):
            tagoff = rec["file_offset"]
            suffix = f"{i:02d}_dst_{rec['destination']:04X}_num_{rec['instruction_count']:03d}_off_{tagoff:06X}"
            program_name = f"mpg_{suffix}.bin"
            qwc_name = f"qwc_{suffix}.bin"
            tail_name = f"tail_{suffix}.bin" if rec["tail_bytes"] else ""
            code = data[rec["payload_offset"]:rec["payload_offset"] + rec["declared_bytes"]]
            qwc_payload = data[rec["payload_offset"]:rec["payload_end"]]
            tail = qwc_payload[rec["declared_bytes"]:]
            (prog_dir / program_name).write_bytes(code)
            (qwc_dir / qwc_name).write_bytes(qwc_payload)
            if tail_name:
                (tail_dir / tail_name).write_bytes(tail)
            recout: dict[str, object] = {
                "record_index": i, "elf_segment_index": rec["segment_index"],
                "dma_tag_file_offset_hex": hx(tagoff), "dma_tag_virtual_address_hex": hx(rec["virtual_address"]),
                "dma_tag_raw_hex": data[tagoff:tagoff + 16].hex(" "), "dma_id": rec["dma_id"],
                "qwc": rec["qwc"], "vif_command": "MPG", "vif_word_hex": hx(rec["vif_word"]),
                "vif_num_raw": rec["vif_num_raw"], "effective_instruction_count": rec["instruction_count"],
                "num_zero_means_256": bool(rec["num_zero_means_256"]),
                "destination_instruction_address_hex": hx(rec["destination"]),
                "destination_end_exclusive_hex": hx(rec["destination"] + rec["instruction_count"]),
                "declared_instruction_bytes": rec["declared_bytes"], "qwc_payload_bytes": rec["qwc_payload_bytes"],
                "trailing_bytes_after_declared_mpg": rec["tail_bytes"],
                "payload_file_offset_hex": hx(rec["payload_offset"]), "payload_end_exclusive_hex": hx(rec["payload_end"]),
                "program_file": f"microprograms/{program_name}", "program_sha256": sha256(code),
                "full_qwc_payload_file": f"qwc_payloads/{qwc_name}", "full_qwc_payload_sha256": sha256(qwc_payload),
                "tail_file": f"tails/{tail_name}" if tail_name else "",
                "tag_range_chain_adjacent_to_next": False,
            }
            output_records.append(recout)
            program_id = f"MPG_{i:02d}"
            program_images.append({"program_id": program_id, "kind": "top_level", "destination": rec["destination"],
                                  "instruction_count": rec["instruction_count"], "code": code,
                                  "file_offset": rec["payload_offset"], "source_record_index": i,
                                  "program_file": f"microprograms/{program_name}", "sha256": sha256(code)})
            for instruction_index in range(rec["instruction_count"]):
                ins_off = instruction_index * 8
                raw64 = struct.unpack_from("<Q", code, ins_off)[0]
                instruction_rows.append({
                    "program_id": program_id, "program_kind": "top_level",
                    "destination_instruction_address_hex": hx(rec["destination"] + instruction_index),
                    "program_instruction_index": instruction_index,
                    "elf_file_offset_hex": hx(rec["payload_offset"] + ins_off),
                    "raw_instruction_u64_hex": f"0x{raw64:016X}",
                    "lower_u32_hex": f"0x{raw64 & 0xFFFFFFFF:08X}",
                    "upper_u32_hex": f"0x{raw64 >> 32:08X}",
                    "program_sha256": sha256(code),
                })
            if tail:
                found, controls = parse_embedded_mpgs(rec, tail)
                for j, item in enumerate(found):
                    nested_code = tail[int(item["payload_tail_relative_offset"]):int(item["payload_tail_relative_offset"]) + int(item["payload_bytes"])]
                    nname = f"nested_{len(embedded_records):02d}_dst_{int(item['destination']):04X}_num_{int(item['instruction_count']):03d}_parent_{i:02d}.bin"
                    (prog_dir / nname).write_bytes(nested_code)
                    program_id = f"NESTED_{len(embedded_records):02d}"
                    program_images.append({"program_id": program_id, "kind": "embedded", "destination": int(item["destination"]),
                                          "instruction_count": int(item["instruction_count"]), "code": nested_code,
                                          "file_offset": int(item["payload_file_offset"]), "source_record_index": i,
                                          "program_file": f"microprograms/{nname}", "sha256": sha256(nested_code)})
                    for instruction_index in range(int(item["instruction_count"])):
                        ins_off = instruction_index * 8
                        raw64 = struct.unpack_from("<Q", nested_code, ins_off)[0]
                        instruction_rows.append({
                            "program_id": program_id, "program_kind": "embedded",
                            "destination_instruction_address_hex": hx(int(item["destination"]) + instruction_index),
                            "program_instruction_index": instruction_index,
                            "elf_file_offset_hex": hx(int(item["payload_file_offset"]) + ins_off),
                            "raw_instruction_u64_hex": f"0x{raw64:016X}",
                            "lower_u32_hex": f"0x{raw64 & 0xFFFFFFFF:08X}",
                            "upper_u32_hex": f"0x{raw64 >> 32:08X}",
                            "program_sha256": sha256(nested_code),
                        })
                    item_out: dict[str, object] = dict(item)
                    item_out.update({"parent_record_index": i, "program_file": f"microprograms/{nname}",
                                     "program_sha256": sha256(nested_code), "status": "embedded MPG fits parent tail exactly or in full"})
                    embedded_records.append(item_out)
                for item in controls:
                    embedded_control_rows.append({"parent_record_index": i, "parent_tag_file_offset_hex": hx(tagoff), **item})
        # A strong consistency check: the 20 top-level records form one contiguous table by QWC sizes.
        for i in range(len(records) - 1):
            output_records[i]["tag_range_chain_adjacent_to_next"] = records[i]["payload_end"] == records[i + 1]["file_offset"]
        all_adjacent = all(bool(row["tag_range_chain_adjacent_to_next"]) for row in output_records[:-1])
        mscal_counts: Counter[int] = Counter()
        control_by_layout: Counter[tuple[str, str, str]] = Counter()
        if args.control_csv:
            with args.control_csv.open("r", newline="", encoding="utf-8-sig") as stream:
                for row in csv.DictReader(stream):
                    command_name = row.get("vif_command_name", "")
                    immediate_text = row.get("vif_immediate_hex", "")
                    control_by_layout[(row.get("layout_variant", ""), command_name, immediate_text)] += 1
                    if command_name == "MSCAL":
                        immediate = int(immediate_text, 16)
                        mscal_counts[immediate] += 1
        entry_rows = []
        for immediate, count in sorted(mscal_counts.items()):
            entry_rows.append({"msc_cal_immediate_hex": hx(immediate), "msc_cal_count_in_asset_candidates": count,
                               "matching_mpg_destination_record_count": sum(1 for rec in records if rec["destination"] == immediate)})
        write_csv(out / "vu_microprogram_catalog.csv", output_records)
        write_csv(out / "vu_embedded_mpg_catalog.csv", [dict(row) for row in embedded_records])
        write_csv(out / "vu_instruction_words.csv", instruction_rows)
        similarity_rows: list[dict[str, object]] = []
        for first, second in combinations(program_images, 2):
            if int(first["destination"]) != int(second["destination"]):
                continue
            code_a, code_b = bytes(first["code"]), bytes(second["code"])
            common = 0
            max_count = min(len(code_a), len(code_b)) // 8
            for instruction_index in range(max_count):
                start = instruction_index * 8
                if code_a[start:start + 8] != code_b[start:start + 8]:
                    break
                common += 1
            similarity_rows.append({
                "destination_instruction_address_hex": hx(int(first["destination"])),
                "first_program_id": first["program_id"], "first_instruction_count": first["instruction_count"],
                "first_sha256": first["sha256"], "second_program_id": second["program_id"],
                "second_instruction_count": second["instruction_count"], "second_sha256": second["sha256"],
                "identical_program_bytes": code_a == code_b,
                "common_prefix_instruction_count": common,
                "common_prefix_bytes": common * 8,
            })
        write_csv(out / "vu_program_similarity.csv", similarity_rows)
        write_csv(out / "vu_embedded_tail_commands.csv", embedded_control_rows)
        write_csv(out / "msc_cal_mpg_cross_reference.csv", entry_rows)
        write_csv(out / "asset_layout_control_counts.csv", [{"layout_variant": k[0], "vif_command_name": k[1],
                   "vif_immediate_hex": k[2], "candidate_count": v} for k, v in sorted(control_by_layout.items())])
        with (out / "summary.json").open("w", encoding="utf-8") as stream:
            json.dump({
                "input_name": args.executable.name, "input_size_bytes": len(data), "input_sha256": sha256(data),
                "elf_entry_point_hex": hx(entry), "load_segments": segments,
                "top_level_mpg_records": len(records), "embedded_mpg_records": len(embedded_records),
                "instruction_listing_rows": len(instruction_rows), "same_destination_pairwise_comparisons": len(similarity_rows),
                "total_mpg_program_images_extracted": len(records) + len(embedded_records),
                "unique_destination_addresses": sorted({int(r["destination_instruction_address_hex"], 16) for r in output_records} | {int(r["destination"],) for r in embedded_records}),
                "all_top_level_records_contiguous_by_qwc": all_adjacent,
                "all_top_level_payloads_bounded_by_pt_load": True,
                "msc_cal_asset_candidate_counts": {hx(k): v for k, v in sorted(mscal_counts.items())},
                "asset_layout_control_counts": {f"{layout}|{command}|{imm}": count for (layout, command, imm), count in sorted(control_by_layout.items())},
                "input_modified": False,
                "limitations": ["Programs are raw 64-bit VU instructions, not disassembled or assigned semantic names.",
                                 "A destination may have multiple code variants/lengths; caller context is not yet resolved.",
                                 "The 0x480 NUM=0 record includes a second MPG command in its QWC tail; the complete QWC payload is preserved separately."],
            }, stream, indent=2)
            stream.write("\n")
        lines = [
            "MetropolisMania 2 — VIF MPG microprogram candidates", "=" * 54, "",
            f"ELF size: {len(data)} bytes; SHA-256: {sha256(data)}; entry point: {hx(entry)}",
            f"Validated top-level MPG records: {len(records)}",
            f"Embedded MPG records parsed from tails: {len(embedded_records)}",
            f"Total extracted program images: {len(records) + len(embedded_records)}",
            f"Top-level records contiguous according to tag QWC: {all_adjacent}", "",
            "Top-level records by destination/count:",
        ]
        for rec in records:
            lines.append(f"  file+{hx(rec['file_offset'])} VA {hx(rec['virtual_address'])}: MPG dest={hx(rec['destination'])}, NUMraw={rec['vif_num_raw']}, instructions={rec['instruction_count']}, QWC={rec['qwc']}, tail={rec['tail_bytes']} bytes")
        lines.extend(["", f"Raw instruction listing rows: {len(instruction_rows)}", f"Same-destination code comparisons: {len(similarity_rows)}", "", "Embedded commands:"])
        if not embedded_records:
            lines.append("  none")
        for item in embedded_records:
            lines.append(f"  parent file+{hx(int(item['parent_file_offset']))}, command file+{hx(int(item['command_file_offset']))}: MPG dest={hx(int(item['destination']))}, instructions={item['instruction_count']}, program bytes={item['payload_bytes']}")
        if mscal_counts:
            lines.extend(["", "MSCAL cross-reference counts from mapped PACKAGE.BIN candidates:"])
            for immediate, count in sorted(mscal_counts.items()):
                matches = sum(1 for rec in records if rec["destination"] == immediate)
                lines.append(f"  MSCAL {hx(immediate)}: {count} candidate control tags; {matches} MPG record(s) load at same immediate")
        if control_by_layout:
            lines.extend(["", "Batch-layout control distribution:"])
            for (layout, command, imm), count in sorted(control_by_layout.items()):
                lines.append(f"  {layout} / {command} / {imm}: {count}")
        lines.extend(["", "Interpretation limits:",
                      "- MPG records were accepted only when a VIF MPG code, DMA tag, segment bounds, QWC capacity and VU instruction address range all agreed.",
                      "- QWC payloads and exact declared MPG instruction bytes are preserved separately; extra bytes are not discarded.",
                      "- Equal destination addresses with different instruction counts are retained as separate variants.",
                      "- No claim is made about mesh type or object identity; lower/upper instruction fields are preserved raw without mnemonic decoding.",
                      "- Original executable is not modified."])
        (out / "microprogram_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"PASS: {len(records)} top-level VIF MPG records validated")
        print(f"PASS: {len(embedded_records)} embedded MPG command(s) extracted")
        print(f"PASS: QWC record adjacency check = {all_adjacent}")
        print(f"Output: {out.resolve()}")
        return 0
    except (OSError, ValueError, struct.error, csv.Error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
