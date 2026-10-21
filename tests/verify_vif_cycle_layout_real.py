#!/usr/bin/env python3
"""Run the VIF cycle-layout extractor on an actual PACKAGE.BIN without modifying it."""
from __future__ import annotations
import csv
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

if len(sys.argv) != 3:
    raise SystemExit('usage: verify_vif_cycle_layout_real.py PACKAGE.BIN TOOL.py')
package = Path(sys.argv[1])
tool = Path(sys.argv[2])
before = hashlib.sha256(package.read_bytes()).hexdigest()
with tempfile.TemporaryDirectory(prefix='datase-vif-layout-test-') as temp:
    out_dir = Path(temp) / 'out'
    subprocess.run([sys.executable, str(tool), '--package-bin', str(package), '--out-dir', str(out_dir)],
                   text=True, capture_output=True, check=True)
    summary = json.loads((out_dir / 'batch_00_05a0_vif_memory_summary.json').read_text(encoding='utf-8'))
    assert summary['vertex_count'] == 60
    assert summary['cycle_cl'] == 4 and summary['cycle_wl'] == 1
    assert summary['record_stride_qwords'] == 4
    assert summary['output_buffer_start_hex'] == '0x0F2'
    assert summary['control_tag_offset'] == 0xCA0
    assert summary['source']['part_b_absolute_offset_hex'] == '0x36A30'
    assert summary['source']['part_b_size_bytes'] == 0x1171E0
    assert summary['input_sha256'] == 'cd6e258e70bbb945cba6960a69ae8d73046a1e7980b4c10e8e21bf812940ef50'
    assert summary['source']['source_package_sha256'] == before
    assert (out_dir / 'batch_00_05a0_vu_memory_tops_relative.bin').stat().st_size == 242 * 16
    with (out_dir / 'batch_00_05a0_vu_vertex_records.csv').open(encoding='utf-8-sig', newline='') as fp:
        rows = list(csv.DictReader(fp))
    assert len(rows) == 60
    assert rows[0]['position_qw_tops_relative_hex'] == '0x002'
    assert rows[0]['normal_qw_tops_relative_hex'] == '0x003'
    assert rows[0]['color_qw_tops_relative_hex'] == '0x004'
    assert rows[0]['stq_qw_tops_relative_hex'] == '0x005'
    assert rows[-1]['stq_qw_tops_relative_hex'] == '0x0F1'
after = hashlib.sha256(package.read_bytes()).hexdigest()
assert before == after, 'the source PACKAGE.BIN changed during read-only analysis'
print('VIF cycle-layout integration: PASS (real PACKAGE.BIN slice, hash, 60 records, 242 QWs, read-only source)')
