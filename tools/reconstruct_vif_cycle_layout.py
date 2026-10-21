#!/usr/bin/env python3
"""Reconstruct one observed VIF1 UNPACK memory layout, read-only.

This tool supports the exact MetropolisMania 2 batch observed at chunk 00,
Part B local offset 0x5A0. It models the already-observed setup commands:
BASE/OFFSET, STROW, STMASK=0x50, then STCYCL CL=4/WL=1 and four UNPACK streams.
It does not emulate the VU instruction program or claim to dump runtime GS output.
"""
from __future__ import annotations
import argparse
import csv
import json
import math
import struct
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 128 * 1024 * 1024
QW_BYTES = 16


def u32_at(data: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(data):
        raise ValueError(f"u32 read out of bounds at {off:#x}")
    return struct.unpack_from('<I', data, off)[0]


def dma_tag(data: bytes, off: int) -> dict[str, int]:
    if off < 0 or off % 16 or off + 16 > len(data):
        raise ValueError(f"DMA tag out of bounds/alignment at {off:#x}")
    w0, w1, v0, v1 = struct.unpack_from('<4I', data, off)
    return {
        'offset': off, 'qwc': w0 & 0xffff, 'id': (w0 >> 28) & 0x7,
        'word0': w0, 'word1': w1, 'vif0': v0, 'vif1': v1,
    }


def vif_cmd(word: int) -> int:
    return (word >> 24) & 0x7f


def require_tag(data: bytes, off: int, qwc: int, vif0_cmd: int | None = None,
                vif1_cmd: int | None = None) -> dict[str, int]:
    tag = dma_tag(data, off)
    if tag['id'] != 1:
        raise ValueError(f"expected DMA CNT tag ID=1 at {off:#x}, got {tag['id']}")
    if tag['qwc'] != qwc:
        raise ValueError(f"QWC mismatch at {off:#x}: got {tag['qwc']}, expected {qwc}")
    if off + 16 + qwc * QW_BYTES > len(data):
        raise ValueError(f"DMA payload overrun at {off:#x}")
    if vif0_cmd is not None and vif_cmd(tag['vif0']) != vif0_cmd:
        raise ValueError(f"VIF0 command mismatch at {off:#x}: {vif_cmd(tag['vif0']):#x}")
    if vif1_cmd is not None and vif_cmd(tag['vif1']) != vif1_cmd:
        raise ValueError(f"VIF1 command mismatch at {off:#x}: {vif_cmd(tag['vif1']):#x}")
    return tag


def unpack_desc(tag: dict[str, int], lane_name: str) -> dict[str, Any]:
    code = tag[lane_name]
    cmd = vif_cmd(code)
    num_raw = (code >> 16) & 0xff
    num = num_raw or 256
    imm = code & 0xffff
    fmt = cmd & 0x0f
    formats = {
        0x0: ('S', 1, 32), 0x1: ('S', 1, 16), 0x2: ('S', 1, 8),
        0x4: ('V2', 2, 32), 0x5: ('V2', 2, 16), 0x6: ('V2', 2, 8),
        0x8: ('V3', 3, 32), 0x9: ('V3', 3, 16), 0xa: ('V3', 3, 8),
        0xc: ('V4', 4, 32), 0xd: ('V4', 4, 16), 0xe: ('V4', 4, 8),
    }
    if fmt not in formats:
        raise ValueError(f"unsupported UNPACK format {fmt:#x} at {tag['offset']:#x}")
    label, components, bits = formats[fmt]
    return {
        'tag_offset': tag['offset'], 'payload_offset': tag['offset'] + 16,
        'qwc': tag['qwc'], 'vif_command_word': code,
        'command': cmd, 'format': f'{label}-{bits}', 'components': components,
        'bits_per_component': bits, 'num': num,
        'addr': imm & 0x3ff, 'usn': (imm >> 14) & 1,
        'flg': (imm >> 15) & 1, 'masked': bool(cmd & 0x10),
        'immediate': imm,
    }


def _payload(data: bytes, desc: dict[str, Any]) -> bytes:
    size = int(desc['qwc']) * QW_BYTES
    start = int(desc['payload_offset'])
    out = data[start:start + size]
    expected = (int(desc['num']) * int(desc['components']) * int(desc['bits_per_component']) + 7) // 8
    if len(out) != size:
        raise ValueError(f"truncated payload at {start:#x}")
    expected_qwc = (expected + 15) // 16
    if expected_qwc != desc['qwc']:
        raise ValueError(f"QWC does not match UNPACK fields at {desc['tag_offset']:#x}")
    if expected > size:
        raise ValueError(f"input fields exceed QWC payload at {start:#x}")
    return out[:expected]


def _decode_component_values(payload: bytes, desc: dict[str, Any]) -> list[tuple[int, ...]]:
    n = int(desc['num']); c = int(desc['components']); bits = int(desc['bits_per_component'])
    if bits == 32:
        fmt = '<' + ('I' if c == 1 else str(c) + 'I')
        flat = struct.unpack('<' + str(n * c) + 'I', payload)
    elif bits == 16:
        signed = not bool(desc['usn'])
        fmt = '<' + str(n * c) + ('h' if signed else 'H')
        flat = struct.unpack(fmt, payload)
    elif bits == 8:
        signed = not bool(desc['usn'])
        fmt = '<' + str(n * c) + ('b' if signed else 'B')
        flat = struct.unpack(fmt, payload)
    else:
        raise ValueError(f"unsupported component width: {bits}")
    return [tuple(int(x) for x in flat[i*c:(i+1)*c]) for i in range(n)]


def _as_u32(value: int) -> int:
    return value & 0xffffffff


def _decode_setup(data: bytes, setup_off: int) -> dict[str, Any]:
    """Validate the real setup sequence directly preceding the observed batch."""
    base_tag = require_tag(data, setup_off, 0, vif0_cmd=0x03, vif1_cmd=0x02)
    base = base_tag['vif0'] & 0xffff
    offset = base_tag['vif1'] & 0xffff
    row_tag = require_tag(data, setup_off + 0x10, 1, vif1_cmd=0x30)
    row_payload_off = setup_off + 0x20
    row = struct.unpack_from('<4I', data, row_payload_off)
    mask_tag = require_tag(data, setup_off + 0x30, 0, vif0_cmd=0x20)
    mask = mask_tag['vif1'] & 0xffffffff  # STMASK consumes the following DWORD as mask data.
    direct_tag = require_tag(data, setup_off + 0x40, 4, vif0_cmd=0x11, vif1_cmd=0x50)
    direct_payload_end = setup_off + 0x50 + 4 * QW_BYTES
    return {
        'setup_start': setup_off, 'base': base, 'offset': offset,
        'row_words': list(row), 'mask': mask,
        'base_offset_sum_mod_1024': (base + offset) & 0x3ff,
        'row_tag_offset': row_tag['offset'], 'row_payload_offset': row_payload_off,
        'mask_tag_offset': mask_tag['offset'], 'direct_tag_offset': direct_tag['offset'],
        'direct_payload_end': direct_payload_end,
        'mask_action_by_lane': [(mask >> (2 * i)) & 3 for i in range(4)],
    }


def reconstruct(data: bytes, batch_off: int = 0x5a0, setup_off: int = 0x510) -> dict[str, Any]:
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds safe limit {MAX_INPUT_BYTES} bytes")
    setup = _decode_setup(data, setup_off)
    if setup['direct_payload_end'] != batch_off:
        raise ValueError(f"setup DIRECT ends at {setup['direct_payload_end']:#x}, not batch {batch_off:#x}")

    tag0 = require_tag(data, batch_off, 2, vif0_cmd=0x01, vif1_cmd=0x6c)
    cycle_imm0 = tag0['vif0'] & 0xffff
    cl = cycle_imm0 & 0xff; wl = (cycle_imm0 >> 8) & 0xff
    if (cl, wl) != (1, 1):
        raise ValueError(f"initial STCYCL expected CL=1/WL=1, got CL={cl}/WL={wl}")
    meta = unpack_desc(tag0, 'vif1')
    meta_payload = _payload(data, meta)
    if meta['num'] != 2 or meta['format'] != 'V4-32' or meta['flg'] != 1 or meta['addr'] != 0:
        raise ValueError('unexpected two-qword metadata UNPACK')

    tag_pos_off = batch_off + 16 + tag0['qwc'] * QW_BYTES
    tag_pos = require_tag(data, tag_pos_off, 30, vif0_cmd=0x01, vif1_cmd=0x6d)
    cyc_imm = tag_pos['vif0'] & 0xffff
    cl = cyc_imm & 0xff; wl = (cyc_imm >> 8) & 0xff
    if (cl, wl) != (4, 1):
        raise ValueError(f"expected STCYCL CL=4/WL=1, got CL={cl}/WL={wl}")

    # Parse the four stream tags in their exact observed order.
    streams: list[dict[str, Any]] = []
    cursor = tag_pos_off
    expected = [
        (0x6d, 0x8002, 30, 'position_like'),
        (0x6d, 0x8003, 30, 'normal_like'),
        (0x6e, 0xc004, 15, 'color_like'),
        (0x74, 0x8005, 30, 'uv_st_like'),
    ]
    for i, (cmd_expected, imm_expected, qwc_expected, slot) in enumerate(expected):
        tag = require_tag(data, cursor, qwc_expected)
        code = tag['vif1']
        if vif_cmd(code) != cmd_expected or (code & 0xffff) != imm_expected:
            raise ValueError(f"UNPACK stream {i} mismatch at {cursor:#x}: cmd={vif_cmd(code):#x}, imm={code & 0xffff:#06x}")
        desc = unpack_desc(tag, 'vif1')
        if desc['flg'] != 1 or desc['addr'] != (imm_expected & 0x3ff):
            raise ValueError(f"stream {slot} is not TOPS-relative as expected")
        if i == 3 and not desc['masked']:
            raise ValueError('V2-32 UV-like stream is expected to use masked UNPACK command 0x74')
        if i != 3 and desc['masked']:
            raise ValueError(f"unexpected masked flag on stream {slot}")
        desc['slot_name'] = slot
        desc['raw_payload'] = _payload(data, desc)
        streams.append(desc)
        cursor += 16 + tag['qwc'] * QW_BYTES

    control_off = cursor
    control_tag = require_tag(data, control_off, 0, vif0_cmd=0x14)
    mscal_imm = control_tag['vif0'] & 0xffff
    if mscal_imm != 0x00b8:
        raise ValueError(f"expected MSCAL 0x00B8 after streams, got {mscal_imm:#x}")
    count = streams[0]['num']
    if any(s['num'] != count for s in streams):
        raise ValueError('UNPACK stream counts differ')
    if count != 60:
        raise ValueError(f"expected observed 60-item stream, got {count}")

    # Build a TOPS-relative VU data-memory image. Unpack conversion expands each
    # source vector into a 128-bit VU qword. CL=4/WL=1 writes one QW then skips 3.
    memory: dict[int, tuple[tuple[int, int, int, int], str, int, int]] = {}
    meta_qws = [struct.unpack_from('<4I', meta_payload, i * 16) for i in range(2)]
    for i, q in enumerate(meta_qws):
        memory[i] = (tuple(q), 'metadata', tag0['offset'], meta['payload_offset'] + i * 16)

    data_by_slot: dict[str, list[tuple[int, ...]]] = {}
    for desc in streams:
        vals = _decode_component_values(desc['raw_payload'], desc)
        data_by_slot[desc['slot_name']] = vals
        for i, value_tuple in enumerate(vals):
            dst = int(desc['addr']) + i * cl  # observed CL=4/WL=1
            if dst in memory:
                raise ValueError(f"destination QW collision at TOPS+{dst:#x}; stream={desc['slot_name']} item={i}")
            lanes: list[int | None] = [None, None, None, None]
            if desc['slot_name'] == 'position_like' or desc['slot_name'] == 'normal_like':
                for j, val in enumerate(value_tuple): lanes[j] = _as_u32(val)
            elif desc['slot_name'] == 'color_like':
                for j, val in enumerate(value_tuple): lanes[j] = _as_u32(val)
            elif desc['slot_name'] == 'uv_st_like':
                for j, val in enumerate(value_tuple): lanes[j] = _as_u32(val)
                # Observed MASK 0x50 = lanes X/Y from data, Z/W from ROW.
                for j, action in enumerate(setup['mask_action_by_lane']):
                    if action == 0:
                        if j >= len(value_tuple):
                            raise ValueError(f"MASK asks for source lane {j}, absent in V2 payload")
                    elif action == 1:
                        lanes[j] = setup['row_words'][j]
                    elif action == 2:
                        raise ValueError('MASK requests COL lane but no STCOL state was validated')
                    elif action == 3:
                        raise ValueError('MASK requests preserve lane; previous VU QW state is not modeled')
            if any(v is None for v in lanes):
                raise ValueError(f"incomplete reconstructed qword for {desc['slot_name']} item {i}: {lanes}")
            memory[dst] = (tuple(int(v) for v in lanes), desc['slot_name'], int(desc['tag_offset']), int(desc['payload_offset']) + i * (desc['components'] * desc['bits_per_component'] // 8))

    expected_qws = set(range(2 + 4 * count))
    if set(memory) != expected_qws:
        missing = sorted(expected_qws - set(memory))
        extra = sorted(set(memory) - expected_qws)
        raise ValueError(f"memory coverage mismatch; missing={missing[:8]} extra={extra[:8]}")

    # The value at metadata QW1 lane0 drives VI10=0xF0 in the inspected VU code.
    stride_qws = int(meta_qws[1][0])
    output_start_rel = 2 + stride_qws
    if stride_qws != count * 4:
        raise ValueError(f"metadata stride {stride_qws:#x} does not equal {count}*4 QWs")

    vertex_rows: list[dict[str, Any]] = []
    pos_desc, nrm_desc, col_desc, uv_desc = streams
    for i in range(count):
        p = data_by_slot['position_like'][i]
        n = data_by_slot['normal_like'][i]
        c = data_by_slot['color_like'][i]
        uv = data_by_slot['uv_st_like'][i]
        s, t = struct.unpack('<2f', struct.pack('<2I', uv[0], uv[1]))
        if not (math.isfinite(s) and math.isfinite(t)):
            raise ValueError(f"non-finite ST float at vertex {i}")
        vertex_rows.append({
            'vertex_index': i,
            'position_qw_tops_relative_hex': f"0x{2 + 4*i:03X}",
            'normal_qw_tops_relative_hex': f"0x{3 + 4*i:03X}",
            'color_qw_tops_relative_hex': f"0x{4 + 4*i:03X}",
            'stq_qw_tops_relative_hex': f"0x{5 + 4*i:03X}",
            'position_x_s16': p[0], 'position_y_s16': p[1], 'position_z_s16': p[2], 'position_w_s16': p[3],
            'position_x_div4096': p[0] / 4096.0, 'position_y_div4096': p[1] / 4096.0, 'position_z_div4096': p[2] / 4096.0,
            'normal_x_s16': n[0], 'normal_y_s16': n[1], 'normal_z_s16': n[2], 'normal_w_s16': n[3],
            'normal_x_div4096': n[0] / 4096.0, 'normal_y_div4096': n[1] / 4096.0, 'normal_z_div4096': n[2] / 4096.0,
            'color_r_u8': c[0], 'color_g_u8': c[1], 'color_b_u8': c[2], 'color_a_u8': c[3],
            's_f32': s, 't_f32': t, 'q_from_row_f32': struct.unpack('<f', struct.pack('<I', setup['row_words'][2]))[0],
            'uv_source_mask_actions': 'DATA,DATA,ROW,ROW',
            'position_payload_offset_hex': f"0x{int(pos_desc['payload_offset']) + i*8:X}",
            'normal_payload_offset_hex': f"0x{int(nrm_desc['payload_offset']) + i*8:X}",
            'color_payload_offset_hex': f"0x{int(col_desc['payload_offset']) + i*4:X}",
            'st_payload_offset_hex': f"0x{int(uv_desc['payload_offset']) + i*8:X}",
        })

    qword_rows: list[dict[str, Any]] = []
    memory_blob = bytearray()
    for addr in range(2 + 4 * count):
        lanes, role, tag_off, payload_off = memory[addr]
        raw = struct.pack('<4I', *lanes)
        memory_blob.extend(raw)
        qword_rows.append({
            'qword_index_from_TOPS': addr,
            'qword_index_hex': f"0x{addr:03X}",
            'role': role,
            'source_tag_offset_hex': f"0x{tag_off:X}",
            'source_payload_offset_hex': f"0x{payload_off:X}",
            'lane0_u32_hex': f"0x{lanes[0]:08X}", 'lane1_u32_hex': f"0x{lanes[1]:08X}",
            'lane2_u32_hex': f"0x{lanes[2]:08X}", 'lane3_u32_hex': f"0x{lanes[3]:08X}",
            'raw_qword_hex': raw.hex(' '),
        })

    return {
        'setup': setup, 'batch_offset': batch_off, 'control_tag_offset': control_off,
        'mscal_immediate': mscal_imm, 'cycle_cl': cl, 'cycle_wl': wl,
        'vertex_count': count, 'record_stride_qwords': 4,
        'input_qword_first_relative': 2, 'input_qword_last_relative': 1 + 4 * count,
        'output_buffer_start_qw_relative_candidate': output_start_rel,
        'output_buffer_start_hex': f"0x{output_start_rel:03X}",
        'memory_image': bytes(memory_blob), 'qword_rows': qword_rows,
        'vertex_rows': vertex_rows, 'streams': [{k:v for k,v in s.items() if k != 'raw_payload'} for s in streams],
        'metadata_qwords': [list(q) for q in meta_qws],
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        raise ValueError(f"refusing to write empty CSV: {path}")
    with path.open('w', newline='', encoding='utf-8-sig') as fp:
        wr = csv.DictWriter(fp, fieldnames=list(rows[0].keys()))
        wr.writeheader(); wr.writerows(rows)


PACKAGE_CHUNK0_PART_B_OFFSET = 0x36A30
PACKAGE_CHUNK0_PART_B_SIZE = 0x1171E0


def write_result(data: bytes, out_dir: Path, input_name: str,
                 batch_off: int = 0x5a0, setup_off: int = 0x510,
                 source_metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    result = reconstruct(data, batch_off, setup_off)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(out_dir / 'batch_00_05a0_vu_memory_qwords.csv', result['qword_rows'])
    write_csv(out_dir / 'batch_00_05a0_vu_vertex_records.csv', result['vertex_rows'])
    (out_dir / 'batch_00_05a0_vu_memory_tops_relative.bin').write_bytes(result['memory_image'])
    summary = {
        k: v for k, v in result.items() if k not in ('memory_image', 'qword_rows', 'vertex_rows', 'streams')
    }
    summary['input_path_name'] = input_name
    summary['input_sha256'] = __import__('hashlib').sha256(data).hexdigest()
    summary['input_size_bytes'] = len(data)
    summary['streams'] = result['streams']
    if source_metadata:
        summary['source'] = source_metadata
    (out_dir / 'batch_00_05a0_vif_memory_summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    return summary


def run(input_path: Path, out_dir: Path, batch_off: int = 0x5a0, setup_off: int = 0x510) -> dict[str, Any]:
    data = input_path.read_bytes()
    return write_result(data, out_dir, input_path.name, batch_off, setup_off)


def run_package(package_path: Path, out_dir: Path, batch_off: int = 0x5a0,
                setup_off: int = 0x510) -> dict[str, Any]:
    package = package_path.read_bytes()
    start = PACKAGE_CHUNK0_PART_B_OFFSET
    end = start + PACKAGE_CHUNK0_PART_B_SIZE
    if end > len(package):
        raise ValueError(f'PACKAGE.BIN too short for chunk 00 Part B: need end {end:#x}, have {len(package):#x}')
    part_b = package[start:end]
    metadata = {
        'source_package_name': package_path.name,
        'source_package_size_bytes': len(package),
        'source_package_sha256': __import__('hashlib').sha256(package).hexdigest(),
        'part_b_absolute_offset_hex': f'0x{start:X}',
        'part_b_size_bytes': len(part_b),
        'part_b_absolute_end_hex': f'0x{end:X}',
    }
    return write_result(part_b, out_dir, package_path.name, batch_off, setup_off, metadata)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    source = ap.add_mutually_exclusive_group(required=True)
    source.add_argument('--part-b', type=Path, help='Extracted chunk_00_part_b.bin (raw bytes; input is never modified)')
    source.add_argument('--package-bin', type=Path, help='Original PACKAGE.BIN; chunk-00 Part B is sliced read-only using the validated range')
    ap.add_argument('--out-dir', type=Path, required=True)
    ap.add_argument('--batch-offset', type=lambda x: int(x, 0), default=0x5a0)
    ap.add_argument('--setup-offset', type=lambda x: int(x, 0), default=0x510)
    args = ap.parse_args()
    try:
        if args.package_bin:
            summary = run_package(args.package_bin, args.out_dir, args.batch_offset, args.setup_offset)
        else:
            summary = run(args.part_b, args.out_dir, args.batch_offset, args.setup_offset)
    except (OSError, ValueError) as exc:
        ap.error(str(exc))
    print(json.dumps({k:summary[k] for k in (
        'vertex_count','record_stride_qwords','cycle_cl','cycle_wl',
        'output_buffer_start_hex','control_tag_offset','metadata_qwords','input_sha256'
    )}, indent=2))
    if 'source' in summary:
        print(json.dumps(summary['source'], indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
