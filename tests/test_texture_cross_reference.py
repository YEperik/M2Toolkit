#!/usr/bin/env python3
"""Synthetic checks for TEX0/TEX2 state merging and conservative texture matching."""
from __future__ import annotations
import importlib.util
import sys
from pathlib import Path
SCRIPT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / 'tools' / 'crossref_prebatch_texture_uploads.py'
spec = importlib.util.spec_from_file_location('crossref_prebatch_texture_uploads', SCRIPT)
mod = importlib.util.module_from_spec(spec); assert spec and spec.loader; spec.loader.exec_module(mod)
regs = [
 {'actual_gs_register':'TEX1_1','packet_offset_hex':'0x570','actual_gs_value_hex':'0x261'},
 {'actual_gs_register':'TEX0_1','packet_offset_hex':'0x580','actual_gs_value_hex':'0x0','tex_tbp0':'9277','tex_tbw':'2','tex_psm_name':'PSMT8','tex_width':'64','tex_height':'32','tex_cbp':'9320','tex_cpsm':'0','tex_csm':'0','tex_csa':'0','tex_cld':'4'},
 {'actual_gs_register':'TEX2_1','packet_offset_hex':'0x590','actual_gs_value_hex':'0x0','tex2_psm_name':'PSMT4','tex2_cbp':'9320','tex2_cpsm':'0','tex2_csm':'0','tex2_csa':'13','tex2_cld':'0'},
]
uploads = [
 {'texture_index':'17','dbp_units':'9277','psm_name':'PSMT4','width':'64','height':'32','payload_size_bytes':'1024','payload_offset_in_package_hex':'0x32FA0'},
 {'texture_index':'31','dbp_units':'9320','psm_name':'PSMCT32','width':'16','height':'16','payload_size_bytes':'1024','payload_offset_in_package_hex':'0x361A0'},
]
rows = mod.cross_reference(regs, uploads)
assert rows[0]['package_absolute_qword_offset_hex']=='0x36FA0'
assert rows[1]['effective_tbp0']==9277 and rows[1]['effective_psm']=='PSMT8'
assert rows[1]['effective_dbp_psm_match']=='false'  # At the intermediate TEX0 write itself.
assert rows[2]['effective_tbp0']==9277 and rows[2]['effective_width']==64
assert rows[2]['effective_psm']=='PSMT4' and rows[2]['effective_dbp_psm_match']=='true'
assert 'texture_index=31' in rows[2]['cbp_upload_candidates']
assert 'CLUT use remains unconfirmed' in rows[2]['evidence_note']
print('Texture cross-reference synthetic: PASS (TEX2 inherits base/dimensions, overrides PSM/CLUT, CBP caveat)')
