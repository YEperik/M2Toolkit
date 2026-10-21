#!/usr/bin/env python3
import csv, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import disassemble_vu
ROOT=Path(__file__).resolve().parents[1]
BIN=ROOT/'samples'/'vu_microprograms'
CAT=ROOT/'samples'/'vu_microprogram_catalog.csv'
if not any(BIN.glob('*.bin')):
    print('SKIP real microprogram integration: extracted game-derived samples are not bundled; recreate from your own SLUS_216.06 using tools/extract_vu_microprogram_candidates.py')
    raise SystemExit(0)
with tempfile.TemporaryDirectory() as td:
    summaries, rows, controls = disassemble_vu.run(BIN,CAT,Path(td))
    assert len(summaries)==21, len(summaries)
    assert len(rows)==2639, len(rows)
    assert sum(int(s['xgkick_count']) for s in summaries)==17
    assert sum(int(s['unknown_lower_count']) for s in summaries)==0
    assert sum(int(s['unknown_upper_count']) for s in summaries)==0
    mpg4=[r for r in rows if r['program_id']=='MPG_04']
    kicks=[r for r in mpg4 if r['is_xgkick']=='true']
    assert len(kicks)==1 and kicks[0]['pc_instruction_address_hex']=='0x0120', kicks
    epoints=[r['pc_instruction_address_hex'] for r in mpg4 if r['is_end_e_bit']=='true']
    assert '0x0121' in epoints, epoints
    branch=[r for r in mpg4 if r['pc_instruction_address_hex']=='0x0119'][0]
    assert branch['branch_target_instruction_address_hex']=='0x0700', branch
    assert branch['target_entry_program_ids']=='MPG_09', branch
    assert branch['target_containing_program_ids']=='MPG_09', branch
print('Real microprogram integration: PASS (21 programs, 2639 instructions, 17 XGKICK)')
