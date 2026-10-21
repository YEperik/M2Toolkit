#!/usr/bin/env python3
import csv, importlib.util, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('link_vif_to_vu', ROOT/'tools'/'link_vif_to_vu.py')
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
with tempfile.TemporaryDirectory() as td:
    td=Path(td)
    controls=td/'controls.csv'; disasm=td/'disassembly.csv'; summary=td/'summary.csv'
    with controls.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=['descriptor_label','chunk_index','batch_start_local_hex','batch_start_package_hex','control_tag_local_hex','control_tag_package_hex','vif_command_name','vif_immediate_hex'])
        w.writeheader(); w.writerow({'descriptor_label':'CHUNK_00_PART_B','chunk_index':'0','batch_start_local_hex':'0x5A0','batch_start_package_hex':'0x36FD0','control_tag_local_hex':'0xCA0','control_tag_package_hex':'0x376D0','vif_command_name':'MSCAL','vif_immediate_hex':'0x00B8'})
        w.writerow({'descriptor_label':'CHUNK_00_PART_B','chunk_index':'0','batch_start_local_hex':'0xCB0','batch_start_package_hex':'0x376E0','control_tag_local_hex':'0x13B0','control_tag_package_hex':'0x37DE0','vif_command_name':'MSCNT','vif_immediate_hex':'0x0000'})
    with disasm.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=['program_id','is_xgkick','is_end_e_bit','pc_instruction_address_hex']);w.writeheader()
        w.writerow({'program_id':'MPG_04','is_xgkick':'true','is_end_e_bit':'false','pc_instruction_address_hex':'0x0120'})
        w.writerow({'program_id':'MPG_04','is_xgkick':'false','is_end_e_bit':'true','pc_instruction_address_hex':'0x0121'})
    with summary.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=['program_id','destination_instruction_address_hex','xgkick_count','instruction_count']);w.writeheader()
        w.writerow({'program_id':'MPG_04','destination_instruction_address_hex':'0x00B8','xgkick_count':'1','instruction_count':'109'})
    links, grouped=mod.run(controls,disasm,summary,td/'out')
    assert len(links)==2
    assert links[0]['matched_program_ids']=='MPG_04'
    assert links[0]['matched_xgkick_pcs']=='0x0120'
    assert 'currently active program' in links[1]['interpretation']
print('VIF-to-VU link synthetic: PASS')
