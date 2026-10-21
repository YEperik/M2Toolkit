#!/usr/bin/env python3
"""Join VIF MSCAL candidates to extracted VU microprogram records by immediate/destination.
Rows are candidate links, not proof that every candidate executes in a real gameplay trace.
"""
from __future__ import annotations
import argparse, csv
from collections import Counter
from pathlib import Path

def read_csv(path):
    with path.open(newline='', encoding='utf-8-sig') as f: return list(csv.DictReader(f))
def write_csv(path, rows):
    if not rows: return
    with path.open('w', newline='', encoding='utf-8-sig') as f:
        w=csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)

def run(controls_path, disasm_path, summary_path, out_dir):
    controls, asmrows, programs = read_csv(controls_path), read_csv(disasm_path), read_csv(summary_path)
    xg_by_id={}
    e_by_id={}
    for r in asmrows:
        if r['is_xgkick']=='true': xg_by_id.setdefault(r['program_id'], []).append(r['pc_instruction_address_hex'])
        if r['is_end_e_bit']=='true': e_by_id.setdefault(r['program_id'], []).append(r['pc_instruction_address_hex'])
    bydest={}
    for p in programs: bydest.setdefault(int(p['destination_instruction_address_hex'],16), []).append(p)
    links=[]; counter=Counter(); chunkcount=Counter()
    for c in controls:
        name=c.get('vif_command_name','')
        if name not in ('MSCAL','MSCNT'): continue
        imm=int(c.get('vif_immediate_hex','0x0'),16)
        matches=bydest.get(imm,[]) if name=='MSCAL' else []
        ids=';'.join(p['program_id'] for p in matches)
        details=';'.join(f"{p['program_id']}@{p['destination_instruction_address_hex']}:xgkick={p['xgkick_count']}:n={p['instruction_count']}" for p in matches)
        row={
          'descriptor_label':c.get('descriptor_label',''), 'chunk_index':c.get('chunk_index',''),
          'batch_start_local_hex':c.get('batch_start_local_hex',''), 'batch_start_package_hex':c.get('batch_start_package_hex',''),
          'control_tag_local_hex':c.get('control_tag_local_hex',''), 'control_tag_package_hex':c.get('control_tag_package_hex',''),
          'vif_command_name':name, 'vif_immediate_hex':f'0x{imm:04X}',
          'matched_program_ids':ids, 'matched_program_details':details,
          'matched_xgkick_pcs':';'.join(pc for p in matches for pc in xg_by_id.get(p['program_id'],[])),
          'matched_end_e_pcs':';'.join(pc for p in matches for pc in e_by_id.get(p['program_id'],[])),
          'interpretation':'MSCAL destination matched extracted MPG record(s)' if matches else ('MSCNT resumes currently active program; caller state required' if name=='MSCNT' else 'no matching extracted MPG record'),
        }
        links.append(row); counter[(name,imm,ids)]+=1; chunkcount[(c.get('descriptor_label',''),name,imm)]+=1
    out_dir.mkdir(parents=True,exist_ok=True)
    write_csv(out_dir/'vif_mscal_program_links.csv',links)
    summary=[]
    for (name,imm,ids),count in sorted(counter.items(),key=lambda x:(x[0][0],x[0][1],x[0][2])):
        summary.append({'vif_command_name':name,'vif_immediate_hex':f'0x{imm:04X}','matched_program_ids':ids,'candidate_count':count,
                        'interpretation':'MSCAL destination match; MSCNT requires active-state trace' if name=='MSCNT' else ('matched' if ids else 'not found')})
    write_csv(out_dir/'vif_mscal_program_link_summary.csv',summary)
    per_chunk=[]
    for (desc,name,imm),count in sorted(chunkcount.items()): per_chunk.append({'descriptor_label':desc,'vif_command_name':name,'vif_immediate_hex':f'0x{imm:04X}','candidate_count':count})
    write_csv(out_dir/'vif_mscal_program_links_by_chunk.csv',per_chunk)
    return links,summary

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--controls',type=Path,required=True); ap.add_argument('--disassembly',type=Path,required=True)
    ap.add_argument('--program-summary',type=Path,required=True); ap.add_argument('--output-dir',type=Path,required=True)
    a=ap.parse_args(); links,summary=run(a.controls,a.disassembly,a.program_summary,a.output_dir)
    print(f'Wrote {len(links)} VIF control candidates and {len(summary)} grouped control mappings')
if __name__=='__main__': main()
