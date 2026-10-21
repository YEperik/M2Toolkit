#!/usr/bin/env python3
"""Synthetic and real-sample regression tests for VIF cycle-layout reconstruction."""
from __future__ import annotations
import importlib.util
import math
import struct
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / 'tools' / 'reconstruct_vif_cycle_layout.py'
spec = importlib.util.spec_from_file_location('reconstruct_vif_cycle_layout', SCRIPT)
mod = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(mod)


def cmd(code: int, num: int = 0, imm: int = 0) -> int:
    return ((code & 0x7f) << 24) | ((num & 0xff) << 16) | (imm & 0xffff)


def put_tag(buf: bytearray, off: int, qwc: int, vif0: int = 0, vif1: int = 0) -> None:
    struct.pack_into('<4I', buf, off, (1 << 28) | qwc, 0, vif0, vif1)


def synthetic_part_b() -> bytes:
    buf = bytearray(0xCA0 + 16)
    # Observed setup sequence: BASE/OFFSET; STROW + one QW; STMASK=0x50; FLUSH/DIRECT.
    put_tag(buf, 0x510, 0, cmd(0x03, 0, 0x002e), cmd(0x02, 0, 0x01ab))
    put_tag(buf, 0x520, 1, 0, cmd(0x30))
    struct.pack_into('<4I', buf, 0x530, 0, 0, 0x3f800000, 0)
    put_tag(buf, 0x540, 0, cmd(0x20), 0x50)  # STMASK consumes VIF1 word as data.
    put_tag(buf, 0x550, 4, cmd(0x11), cmd(0x50, 0, 4))
    buf[0x560:0x5a0] = bytes([0xaa]) * 64

    # Two control QWs: the first lane of QW1 is the observed 0xF0 QW stride.
    put_tag(buf, 0x5a0, 2, cmd(0x01, 0, 0x0101), cmd(0x6c, 2, 0x8000))
    struct.pack_into('<8I', buf, 0x5b0,
        0x803c, 0x302e4000, 0x412, 0,
        0xf0, 0x384, 0, 0x302ec000)

    # 60 V4-16 values: signed position candidates.
    pos = bytearray()
    nrm = bytearray()
    col = bytearray()
    uv = bytearray()
    for i in range(60):
        pos += struct.pack('<4h', i - 30, 2 * i, -i, 0)
        nrm += struct.pack('<4h', 0, 0, 4096, 4096)
        col += bytes((32, 34, 36, 128))
        uv += struct.pack('<2f', float(i) + 0.25, float(i) + 0.5)

    put_tag(buf, 0x5d0, 30, cmd(0x01, 0, 0x0104), cmd(0x6d, 60, 0x8002))
    buf[0x5e0:0x7c0] = pos
    put_tag(buf, 0x7c0, 30, 0, cmd(0x6d, 60, 0x8003))
    buf[0x7d0:0x9b0] = nrm
    put_tag(buf, 0x9b0, 15, 0, cmd(0x6e, 60, 0xc004))
    buf[0x9c0:0xab0] = col
    put_tag(buf, 0xab0, 30, 0, cmd(0x74, 60, 0x8005))
    buf[0xac0:0xca0] = uv
    put_tag(buf, 0xca0, 0, cmd(0x14, 0, 0x00b8), 0)
    return bytes(buf)


result = mod.reconstruct(synthetic_part_b())
assert result['vertex_count'] == 60
assert result['cycle_cl'] == 4 and result['cycle_wl'] == 1
assert result['record_stride_qwords'] == 4
assert result['output_buffer_start_hex'] == '0x0F2'
assert len(result['memory_image']) == 242 * 16
assert len(result['qword_rows']) == 242 and len(result['vertex_rows']) == 60
assert [int(result['vertex_rows'][i]['position_qw_tops_relative_hex'], 16) for i in range(3)] == [2, 6, 10]
assert [int(result['vertex_rows'][i]['normal_qw_tops_relative_hex'], 16) for i in range(3)] == [3, 7, 11]
assert [int(result['vertex_rows'][i]['color_qw_tops_relative_hex'], 16) for i in range(3)] == [4, 8, 12]
assert [int(result['vertex_rows'][i]['stq_qw_tops_relative_hex'], 16) for i in range(3)] == [5, 9, 13]
# Verify sign extension, unsigned colour lanes, and the MASK/ROW-filled Q and W lanes.
qws = {r['qword_index_from_TOPS']: r for r in result['qword_rows']}
assert qws[2]['lane0_u32_hex'] == '0xFFFFFFE2'
assert qws[4]['lane0_u32_hex'] == '0x00000020'
assert qws[4]['lane3_u32_hex'] == '0x00000080'
assert qws[5]['lane2_u32_hex'] == '0x3F800000'
assert qws[5]['lane3_u32_hex'] == '0x00000000'
assert result['setup']['mask_action_by_lane'] == [0, 0, 1, 1]
assert result['setup']['row_words'] == [0, 0, 0x3f800000, 0]
# Bad QWC must fail closed.
bad = bytearray(synthetic_part_b())
struct.pack_into('<I', bad, 0x5d0, (1 << 28) | 29)
try:
    mod.reconstruct(bytes(bad))
except ValueError:
    pass
else:
    raise AssertionError('bad QWC was accepted')
print('VIF cycle-layout synthetic: PASS (4-QW stride, MASK/ROW, output boundary, malformed QWC rejection)')
