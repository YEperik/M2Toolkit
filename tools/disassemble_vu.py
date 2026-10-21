#!/usr/bin/env python3
"""Conservative static decoder for PS2 VU 64-bit microinstructions.

The binary layout is eight bytes per instruction: low/lower word first, then
upper word (little-endian ELF/DMA payload representation). This tool emits raw
words alongside best-effort mnemonics so unknown/ambiguous encodings remain auditable.
It does not emulate the VU pipeline, delay slots, hazards, or micro-memory writes.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import re
import struct
from collections import Counter
from pathlib import Path
from typing import Optional

FIELD_NAMES = {0: "", 1: "w", 2: "z", 3: "zw", 4: "y", 5: "yw", 6: "yz", 7: "yzw",
               8: "x", 9: "xw", 10: "xz", 11: "xzw", 12: "xy", 13: "xyw", 14: "xyz", 15: "xyzw"}
COMPONENTS = ("x", "y", "z", "w")


def vf(n: int) -> str: return f"vf{n}"
def vi(n: int) -> str: return f"vi{n}"
def flags(upper: int) -> str:
    # VU upper instruction special bits: E/M/D/T at bits 30..27; I is bit31.
    names = []
    for mask, name in ((1 << 30, "E"), (1 << 29, "M"), (1 << 28, "D"), (1 << 27, "T")):
        if upper & mask: names.append(name)
    return "".join(names)


def mask_suffix(word: int) -> str:
    return FIELD_NAMES[(word >> 21) & 0xF]


def comp2(value: int) -> str:
    return COMPONENTS[value & 3]


def decode_upper(word: int, lower: int) -> tuple[str, str, bool]:
    """Return (mnemonic, flags, is_end). Unknown operations preserve raw opcode."""
    fl = flags(word)
    e = bool(word & (1 << 30))
    if word & (1 << 31):
        f = struct.unpack('<f', struct.pack('<I', lower))[0]
        return f"loi 0x{lower:08X} ; immediate-f32={f:.8g}", fl, e

    op = word & 0x3F
    fd, fs, ft = (word >> 6) & 0x1F, (word >> 11) & 0x1F, (word >> 16) & 0x1F
    mask = mask_suffix(word)
    suff = f".{mask}" if mask else ""

    # Broadcast FMAC operations; the low two opcode bits select ft.x/y/z/w.
    bcast_groups = {0x00: "add", 0x04: "sub", 0x08: "madd", 0x0C: "msub",
                    0x10: "max", 0x14: "mini", 0x18: "mul"}
    for base, name in bcast_groups.items():
        if base <= op <= base + 3:
            bc = COMPONENTS[op - base]
            return f"{name}{bc}{suff} {vf(fd)}, {vf(fs)}, {vf(ft)}.{bc}", fl, e

    two = {0x1C: ("mulq", "Q"), 0x1D: ("maxi", "I"), 0x1E: ("muli", "I"), 0x1F: ("minii", "I"),
           0x20: ("addq", "Q"), 0x21: ("maddq", "Q"), 0x22: ("addi", "I"), 0x23: ("maddi", "I"),
           0x24: ("subq", "Q"), 0x25: ("msubq", "Q"), 0x26: ("subi", "I"), 0x27: ("msubi", "I")}
    if op in two:
        name, special = two[op]
        return f"{name}{suff} {vf(fd)}, {vf(fs)}, {special}", fl, e
    regular = {0x28: "add", 0x29: "madd", 0x2A: "mul", 0x2B: "max", 0x2C: "sub", 0x2D: "msub", 0x2F: "mini"}
    if op in regular:
        return f"{regular[op]}{suff} {vf(fd)}, {vf(fs)}, {vf(ft)}", fl, e
    if op == 0x2E:
        return f"opmsub.xyz {vf(fd)}, {vf(fs)}, {vf(ft)}", fl, e

    if 0x3C <= op <= 0x3F:
        sop = (word & 0x3) | ((word >> 4) & 0x7C)
        # Special upper pipeline instructions.
        bc = COMPONENTS[sop & 3]
        if 0x00 <= sop <= 0x03: return f"adda{bc}{suff} {vf(fs)}, {vf(ft)}.{bc}", fl, e
        if 0x04 <= sop <= 0x07: return f"suba{bc}{suff} {vf(fs)}, {vf(ft)}.{bc}", fl, e
        if 0x08 <= sop <= 0x0B: return f"madda{bc}{suff} {vf(fs)}, {vf(ft)}.{bc}", fl, e
        if 0x0C <= sop <= 0x0F: return f"msuba{bc}{suff} {vf(fs)}, {vf(ft)}.{bc}", fl, e
        if 0x10 <= sop <= 0x17:
            conv = {0x10: "itof0", 0x11: "itof4", 0x12: "itof12", 0x13: "itof15",
                    0x14: "ftoi0", 0x15: "ftoi4", 0x16: "ftoi12", 0x17: "ftoi15"}[sop]
            return f"{conv}{suff} {vf(fd)}, {vf(fs)}", fl, e
        if 0x18 <= sop <= 0x1B: return f"mula{bc} {vf(fs)}, {vf(ft)}.{bc}", fl, e
        fixed = {0x1C: f"mulaq ACC, {vf(fs)}, Q", 0x1D: f"abs{suff} {vf(fd)}, {vf(fs)}",
                 0x1E: f"mulai ACC, {vf(fs)}, I", 0x1F: f"clipw.xyz {vf(fs)}, {vf(ft)}",
                 0x20: f"addaq ACC, {vf(fs)}, Q", 0x21: f"maddaq ACC, {vf(fs)}, Q",
                 0x22: f"addai ACC, {vf(fs)}, I", 0x23: f"maddai ACC, {vf(fs)}, I",
                 0x25: f"msubaq ACC, {vf(fs)}, Q", 0x26: f"subai ACC, {vf(fs)}, I",
                 0x27: f"msubai ACC, {vf(fs)}, I", 0x28: f"adda{suff} ACC, {vf(fs)}, {vf(ft)}",
                 0x29: f"madda{suff} ACC, {vf(fs)}, {vf(ft)}", 0x2A: f"mula{suff} ACC, {vf(fs)}, {vf(ft)}",
                 0x2C: f"suba{suff} ACC, {vf(fs)}, {vf(ft)}", 0x2D: f"msuba{suff} ACC, {vf(fs)}, {vf(ft)}",
                 0x2E: f"opmula.xyz ACC, {vf(fs)}, {vf(ft)}", 0x2F: "nop"}
        return fixed.get(sop, f"upper.special_0x{sop:02X} raw=0x{word:08X}"), fl, e
    return f"upper.unknown_op_0x{op:02X} raw=0x{word:08X}", fl, e


def decode_lower(word: int, upper: int) -> tuple[str, str, bool]:
    """Return (mnemonic, category, is_xgkick). Lower is suppressed when upper I-bit is set."""
    if upper & (1 << 31):
        return "<lower ignored: I-bit/LOI>", "immediate", False
    if word == 0x8000033C:
        return "nop", "nop", False
    d = (word >> 6) & 0x1F
    s = (word >> 11) & 0x1F
    t = (word >> 16) & 0x1F
    mask = mask_suffix(word)
    suffix = f".{mask}" if mask else ""

    if word & 0x80000000:
        op = word & 0x3F
        if op in (0x30, 0x31, 0x32, 0x34, 0x35):
            if op == 0x30: return f"iadd {vi(d & 0xF)}, {vi(s & 0xF)}, {vi(t & 0xF)}", "integer", False
            if op == 0x31: return f"isub {vi(d & 0xF)}, {vi(s & 0xF)}, {vi(t & 0xF)}", "integer", False
            if op == 0x32:
                dest, src, imm = (word >> 16) & 0xF, (word >> 11) & 0xF, (word >> 6) & 0x1F
                simm = imm - 32 if imm & 0x10 else imm
                return f"iaddi {vi(dest)}, {vi(src)}, {simm}", "integer", False
            if op == 0x34: return f"iand {vi(d & 0xF)}, {vi(s & 0xF)}, {vi(t & 0xF)}", "integer", False
            return f"ior {vi(d & 0xF)}, {vi(s & 0xF)}, {vi(t & 0xF)}", "integer", False
        subop = (word & 0x3) | ((word >> 4) & 0x7C)
        # Vector/integer transfer and special unit instructions.
        if subop == 0x30: return f"move{suffix} {vf(d)}, {vf(s)}", "vector_move", False
        if subop == 0x31: return f"mr32{suffix} {vf(d)}, {vf(s)}", "vector_move", False
        if subop == 0x34: return f"lqi {vf(d)}, ({vi(s & 0xF)}++)", "load", False
        if subop == 0x35: return f"sqi {vf(d)}, ({vi(s & 0xF)}++)", "store", False
        if subop == 0x36: return f"lqd {vf(d)}, (--{vi(s & 0xF)})", "load", False
        if subop == 0x37: return f"sqd {vf(d)}, (--{vi(s & 0xF)})", "store", False
        if subop in (0x38, 0x39, 0x3A):
            fsf, ftf = (word >> 21) & 3, (word >> 23) & 3
            if subop == 0x38: return f"div Q, {vf(s)}.{comp2(fsf)}, {vf(t)}.{comp2(ftf)}", "efpu", False
            if subop == 0x39: return f"sqrt Q, {vf(s)}.{comp2(fsf)}", "efpu", False
            return f"rsqrt Q, {vf(s)}.{comp2(fsf)}, {vf(t)}.{comp2(ftf)}", "efpu", False
        if subop == 0x3B: return "waitq", "efpu", False
        if subop == 0x3C: return f"mtir {vi((word >> 16) & 0xF)}, {vf(s)}.{comp2((word >> 21) & 3)}", "transfer", False
        if subop == 0x3D: return f"mfir{suffix} {vf(t)}, {vi(s & 0xF)}", "transfer", False
        if subop == 0x3E: return f"ilwr {vi((word >> 16) & 0xF)}, ({vi(s & 0xF)}++)", "load", False
        if subop == 0x3F: return f"iswr {vi((word >> 16) & 0xF)}, ({vi(s & 0xF)}++)", "store", False
        if subop == 0x40: return f"rnext {vi((word >> 16) & 0xF)}", "random", False
        if subop == 0x41: return f"rget {vi((word >> 16) & 0xF)}", "random", False
        if subop == 0x42: return f"rinit {vf(s)}.{comp2((word >> 21) & 3)}", "random", False
        if subop == 0x43: return f"rxor {vf(s)}.{comp2((word >> 21) & 3)}", "random", False
        if subop == 0x64: return f"mfp{suffix} {vf(t)}, P", "transfer", False
        if subop == 0x68: return f"xtop {vi(t & 0xF)}", "special", False
        if subop == 0x69: return f"xitop {vi(t & 0xF)}", "special", False
        if subop == 0x6C: return f"xgkick {vi(s & 0xF)}", "gs_output", True
        efpu = {0x70:"esadd",0x71:"ersadd",0x72:"eleng",0x73:"erleng",0x74:"eatanxy",0x75:"eatanxz",0x76:"esum",0x78:"esqrt",0x79:"ersqrt",0x7A:"ercpr",0x7B:"waitp",0x7C:"esin",0x7D:"eatan",0x7E:"eexp"}
        if subop in efpu:
            name=efpu[subop]
            return (f"{name} P" if name=="waitp" else f"{name} P, {vf(s)}"), "efpu", False
        return f"lower.special_0x{subop:02X} raw=0x{word:08X}", "unknown", False

    op = (word >> 25) & 0x7F
    imm11 = word & 0x7FF
    disp = imm11 - 0x800 if imm11 & 0x400 else imm11
    if op in (0x00, 0x01, 0x04, 0x05):
        name = {0x00:"lq",0x01:"sq",0x04:"ilw",0x05:"isw"}[op]
        if op in (0x00,0x01): return f"{name} {vf(t)}, {disp*16}({vi(s & 0xF)})", "load" if op==0 else "store", False
        return f"{name} {vi(t & 0xF)}, {disp*16}({vi(s & 0xF)})", "load" if op==4 else "store", False
    if op in (0x08, 0x09):
        imm = (word & 0x7FF) | (((word >> 21) & 0xF) << 11)
        return f"{'iaddiu' if op==8 else 'isubiu'} {vi(t & 0xF)}, {vi(s & 0xF)}, 0x{imm:X}", "integer", False
    if op in (0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x1A,0x1B,0x1C):
        name={0x10:"fceq",0x11:"fcset",0x12:"fcand",0x13:"fcor",0x14:"fseq",0x15:"fsset",0x16:"fsand",0x17:"fsor",0x18:"fmeq",0x1A:"fmand",0x1B:"fmor",0x1C:"fcget"}[op]
        return f"{name} imm=0x{imm11:X}", "flags", False
    if op in (0x20,0x21,0x24,0x25):
        name={0x20:"b",0x21:"bal",0x24:"jr",0x25:"jalr"}[op]
        if name in ("b","bal"): return f"{name} rel_imm=0x{imm11:03X} (target unresolved)", "branch", False
        return f"{name} {vi(s & 0xF)}" + (f", {vi(t & 0xF)}" if name=="jalr" else ""), "branch", False
    if op in (0x28,0x29):
        return f"{'ibeq' if op==0x28 else 'ibne'} {vi(t & 0xF)}, {vi(s & 0xF)}, rel_imm=0x{imm11:03X} (target unresolved)", "branch", False
    if op in (0x2C,0x2D,0x2E,0x2F):
        names={0x2C:"ibltz",0x2D:"ibgtz",0x2E:"iblez",0x2F:"ibgez"}
        return f"{names[op]} {vi(s & 0xF)}, rel_imm=0x{imm11:03X} (target unresolved)", "branch", False
    return f"lower.unknown_op_0x{op:02X} raw=0x{word:08X}", "unknown", False



def relative_branch_target(word: int, pc_instruction_address: int) -> Optional[int]:
    """Compute VU relative branch target in instruction slots, including delay slot.

    VU branch imm11 is a signed displacement from the instruction in the delay slot,
    which is PC+1. VU1 has 0x800 64-bit instruction slots, so the computed address
    wraps in that address space. Register-indirect JR/JALR have no relative target.
    """
    if word & 0x80000000:
        return None
    op = (word >> 25) & 0x7F
    if op not in (0x20, 0x21, 0x28, 0x29, 0x2C, 0x2D, 0x2E, 0x2F):
        return None
    imm11 = word & 0x7FF
    displacement = imm11 - 0x800 if imm11 & 0x400 else imm11
    return (pc_instruction_address + 1 + displacement) & 0x7FF

def disassemble_program(data: bytes, program_id: str, kind: str, destination: int, source_file: str,
                        payload_file_offset: Optional[int] = None):
    if not data or len(data) % 8:
        raise ValueError(f"{source_file}: program size must be a nonzero multiple of 8 bytes (got {len(data)})")
    rows, asm, counts = [], [], Counter()
    asm.append(f"; {program_id} ({kind}) source={source_file} size=0x{len(data):X}")
    asm.append(f"; destination instruction address=0x{destination:04X}; words shown as LOWER || UPPER")
    for i in range(0, len(data), 8):
        lower, upper = struct.unpack_from('<II', data, i)
        idx = i // 8
        pc = destination + idx
        lower_text, lower_cat, xgkick = decode_lower(lower, upper)
        upper_text, upper_flags, e_bit = decode_upper(upper, lower)
        branch_target = relative_branch_target(lower, pc) if lower_cat == 'branch' else None
        if branch_target is not None:
            imm11 = lower & 0x7FF
            lower_text = lower_text.replace(
                f"rel_imm=0x{imm11:03X} (target unresolved)",
                f"rel_imm=0x{imm11:03X} target=0x{branch_target:04X}")
        counts[f"lower_cat:{lower_cat}"] += 1
        counts[f"upper:{upper_text.split()[0]}"] += 1
        if xgkick: counts['xgkick'] += 1
        if e_bit: counts['e_bit'] += 1
        if lower_cat == 'unknown': counts['unknown_lower'] += 1
        if upper_text.startswith('upper.unknown') or upper_text.startswith('upper.special_'): counts['unknown_upper'] += 1
        absolute = (payload_file_offset + i) if payload_file_offset is not None else None
        rows.append({
            'program_id':program_id,'program_kind':kind,'source_file':source_file,
            'destination_instruction_address_hex':f'0x{destination:04X}',
            'pc_instruction_address_hex':f'0x{pc:04X}','instruction_index':idx,
            'program_byte_offset_hex':f'0x{i:04X}',
            'source_file_offset_hex':f'0x{absolute:08X}' if absolute is not None else '',
            'raw_lower_u32_hex':f'0x{lower:08X}','raw_upper_u32_hex':f'0x{upper:08X}',
            'lower_mnemonic':lower_text,'lower_category':lower_cat,'upper_mnemonic':upper_text,
            'upper_flags':upper_flags,'is_xgkick':str(xgkick).lower(),'is_end_e_bit':str(e_bit).lower(),
            'branch_target_instruction_address_hex':f'0x{branch_target:04X}' if branch_target is not None else '',
            'target_entry_program_ids':'','target_containing_program_ids':'',
        })
        pcstr = f"{pc:04X}" if pc <= 0xFFFF else f"{pc:X}"
        asm.append(f"{pcstr}: {lower:08X} || {upper:08X}    {lower_text:<48} | {upper_text}{(' ['+upper_flags+']') if upper_flags else ''}")
    summary = {
      'program_id':program_id,'program_kind':kind,'source_file':source_file,
      'destination_instruction_address_hex':f'0x{destination:04X}',
      'instruction_count':len(rows),'source_bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
      'xgkick_count':counts['xgkick'],'e_bit_count':counts['e_bit'],
      'unknown_lower_count':counts['unknown_lower'],'unknown_upper_count':counts['unknown_upper'],
      'load_count':counts['lower_cat:load'],'store_count':counts['lower_cat:store'],
      'branch_count':counts['lower_cat:branch'],'vector_move_count':counts['lower_cat:vector_move'],
      'gs_output_count':counts['lower_cat:gs_output'],
      'lower_category_histogram':json.dumps({k.split(':',1)[1]:v for k,v in counts.items() if k.startswith('lower_cat:')},sort_keys=True),
      'upper_mnemonic_histogram':json.dumps({k.split(':',1)[1]:v for k,v in counts.items() if k.startswith('upper:')},sort_keys=True),
    }
    return rows, asm, summary


def load_catalog(catalog_path: Path):
    if not catalog_path.exists(): return []
    with catalog_path.open(newline='',encoding='utf-8') as f: return list(csv.DictReader(f))


def run(input_dir: Path, catalog_path: Optional[Path], out_dir: Path):
    out_dir.mkdir(parents=True,exist_ok=True)
    asm_dir=out_dir/'asm'; asm_dir.mkdir(exist_ok=True)
    program_records=[]
    # Top-level program metadata if present.
    cat_by_file={}
    if catalog_path and catalog_path.exists():
        for row in load_catalog(catalog_path): cat_by_file[row['program_file'].replace('\\','/').split('/')[-1]]=row
    # Embedded catalog metadata is optional.
    embed_path=(catalog_path.parent/'vu_embedded_mpg_catalog.csv') if catalog_path else None
    embed_by_file={}
    if embed_path and embed_path.exists():
        for row in load_catalog(embed_path): embed_by_file[row['program_file'].replace('\\','/').split('/')[-1]]=row
    all_rows, summaries, controls = [], [], []
    bin_files=sorted(input_dir.glob('*.bin'))
    if not bin_files: raise ValueError(f"No .bin program images found in {input_dir}")
    for path in bin_files:
        meta=cat_by_file.get(path.name)
        embedded=embed_by_file.get(path.name)
        idx_match=re.search(r'mpg_(\d+)_dst_([0-9A-Fa-f]+)_num_(\d+)',path.name)
        nested_match=re.search(r'nested_(\d+)_dst_([0-9A-Fa-f]+)_num_(\d+)',path.name)
        if meta:
            progid=f"MPG_{int(meta['record_index']):02d}"; kind='top_level'
            dest=int(meta['destination_instruction_address_hex'],16)
            payloadoff=int(meta['payload_file_offset_hex'],16)
        elif embedded:
            progid=f"NESTED_{int(embedded.get('parent_record_index','0')):02d}"; kind='embedded'
            dest=int(embedded['destination'],10) if not str(embedded['destination']).startswith('0x') else int(embedded['destination'],16)
            payloadoff=int(embedded['payload_file_offset'],10)
        else:
            m=idx_match or nested_match
            if not m: continue
            progid=f"BIN_{m.group(1)}"; kind='unknown'; dest=int(m.group(2),16); payloadoff=None
        rows,asm,summary=disassemble_program(path.read_bytes(),progid,kind,dest,path.name,payloadoff)
        all_rows.extend(rows); summaries.append(summary)
        (asm_dir/(path.stem+'.asm')).write_text('\n'.join(asm)+'\n',encoding='utf-8')
        for r in rows:
            if r['is_xgkick']=='true' or r['is_end_e_bit']=='true' or r['lower_category']=='branch':
                controls.append({**r,'control_kind': 'XGKICK' if r['is_xgkick']=='true' else ('E-bit' if r['is_end_e_bit']=='true' else 'branch')})
    if not summaries: raise ValueError('No matching microprogram images found')
    # Annotate branch targets only after all images are known. Multiple extracted
    # variants may share a destination address, so candidates are intentionally plural.
    program_ranges = []
    for summary in summaries:
        base = int(summary['destination_instruction_address_hex'], 16)
        end = base + int(summary['instruction_count'])
        program_ranges.append((summary['program_id'], base, end))
    for row in all_rows:
        target_hex = row['branch_target_instruction_address_hex']
        if not target_hex:
            continue
        target = int(target_hex, 16)
        exact = [pid for pid, base, _ in program_ranges if base == target]
        containing = [pid for pid, base, end in program_ranges if base <= target < end]
        row['target_entry_program_ids'] = ';'.join(exact)
        row['target_containing_program_ids'] = ';'.join(containing)
    def write_csv(path, rows):
        if not rows: return
        with path.open('w',newline='',encoding='utf-8-sig') as f:
            w=csv.DictWriter(f,fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    write_csv(out_dir/'microprogram_disassembly.csv',all_rows)
    write_csv(out_dir/'microprogram_summary.csv',summaries)
    write_csv(out_dir/'microprogram_control_flow.csv',controls)
    report=["# VU microprogram disassembly summary", "", f"- Programs decoded: {len(summaries)}", f"- Instructions decoded: {len(all_rows)}",
            f"- XGKICK instructions: {sum(int(s['xgkick_count']) for s in summaries)}",f"- Upper E-bit instructions: {sum(int(s['e_bit_count']) for s in summaries)}",
            f"- Unknown lower instructions: {sum(int(s['unknown_lower_count']) for s in summaries)}", f"- Unknown upper instructions: {sum(int(s['unknown_upper_count']) for s in summaries)}", "",
            "The decoder is static and conservative. It preserves raw words and marks unknown encodings; it does not emulate VU hazards, delay slots, or GS output packets.", "",
            "## Per-program summary", "", "| Program | Destination | Instructions | XGKICK | E-bit | Branches | Loads | Stores | Unknown lower | Unknown upper |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for s in summaries:
        report.append(f"| {s['program_id']} | {s['destination_instruction_address_hex']} | {s['instruction_count']} | {s['xgkick_count']} | {s['e_bit_count']} | {s['branch_count']} | {s['load_count']} | {s['store_count']} | {s['unknown_lower_count']} | {s['unknown_upper_count']} |")
    (out_dir/'disassembly_summary.md').write_text('\n'.join(report)+'\n',encoding='utf-8')
    (out_dir/'summary.json').write_text(json.dumps({'program_count':len(summaries),'instruction_count':len(all_rows),'programs':summaries},indent=2)+'\n',encoding='utf-8')
    return summaries, all_rows, controls


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input-dir',type=Path,required=True,help='Directory containing extracted .bin microprogram images')
    ap.add_argument('--catalog',type=Path,help='vu_microprogram_catalog.csv (embedded catalog expected alongside it)')
    ap.add_argument('--output-dir',type=Path,required=True)
    args=ap.parse_args()
    summaries, rows, controls=run(args.input_dir,args.catalog,args.output_dir)
    print(f"Decoded {len(summaries)} programs / {len(rows)} instructions; controls={len(controls)}")
    print(f"Unknown lower={sum(int(s['unknown_lower_count']) for s in summaries)}, upper={sum(int(s['unknown_upper_count']) for s in summaries)}")

if __name__=='__main__': main()
