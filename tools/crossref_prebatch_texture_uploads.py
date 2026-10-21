#!/usr/bin/env python3
"""Cross-reference decoded GS TEX register writes to a texture-upload catalog.

The TEX2 register does not encode TBP0/TBW/TW/TH. This tool keeps its raw fields
separate and creates an *effective candidate context* by retaining the preceding
TEX0 fields for the same GS context while applying TEX2's PSM/CLUT fields. That
merge is an interpretation of the ordered register writes, not proof of a material.
"""
from __future__ import annotations
import argparse
import csv
from pathlib import Path
from typing import Any


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding='utf-8-sig', newline='') as fp:
        return list(csv.DictReader(fp))


def parse_int(value: str, field: str) -> int:
    try:
        return int(value, 0) if value.lower().startswith('0x') else int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f'invalid {field}: {value!r}') from exc


def context_id(register_name: str) -> str:
    return '2' if register_name.endswith('_2') else '1'


def candidate_text(matches: list[dict[str, str]]) -> str:
    return '; '.join(
        f"texture_index={u['texture_index']} {u['psm_name']} {u['width']}x{u['height']} "
        f"size={u['payload_size_bytes']}B package_offset={u['payload_offset_in_package_hex']}"
        for u in matches)


def cross_reference(registers: list[dict[str, str]], uploads: list[dict[str, str]],
                    package_region_offset: int = 0x36A30) -> list[dict[str, Any]]:
    by_dbp: dict[int, list[dict[str, str]]] = {}
    for upload in uploads:
        needed = ('dbp_units', 'texture_index', 'psm_name', 'width', 'height',
                  'payload_size_bytes', 'payload_offset_in_package_hex')
        if any(k not in upload or not upload[k] for k in needed):
            raise ValueError('upload catalog is missing required fields')
        by_dbp.setdefault(parse_int(upload['dbp_units'], 'upload DBP'), []).append(upload)

    context_state: dict[str, dict[str, Any]] = {}
    out: list[dict[str, Any]] = []
    for reg in registers:
        name = reg.get('actual_gs_register') or reg.get('reg_name') or ''
        raw_offset = reg.get('packet_offset_hex', '')
        absolute_offset = package_region_offset + parse_int(raw_offset, 'packet offset')
        row: dict[str, Any] = {
            'gs_register': name,
            'part_b_local_packet_qword_offset_hex': raw_offset,
            'package_absolute_qword_offset_hex': f'0x{absolute_offset:X}',
            'gs_register_value_u64_hex': reg.get('actual_gs_value_hex') or reg.get('data_u64_hex', ''),
            'raw_tex0_tbp0': reg.get('tex_tbp0', ''), 'raw_tex0_tbw': reg.get('tex_tbw', ''),
            'raw_tex0_psm': reg.get('tex_psm_name', ''), 'raw_tex0_width': reg.get('tex_width', ''),
            'raw_tex0_height': reg.get('tex_height', ''), 'raw_tex2_psm': reg.get('tex2_psm_name', ''),
            'raw_cbp': reg.get('tex_cbp', '') or reg.get('tex2_cbp', ''),
            'raw_cpsm': reg.get('tex_cpsm', '') or reg.get('tex2_cpsm', ''),
            'raw_csm': reg.get('tex_csm', '') or reg.get('tex2_csm', ''),
            'raw_csa': reg.get('tex_csa', '') or reg.get('tex2_csa', ''),
            'raw_cld': reg.get('tex_cld', '') or reg.get('tex2_cld', ''),
            'effective_context': context_id(name) if name in ('TEX0_1','TEX0_2','TEX2_1','TEX2_2') else '',
            'effective_tbp0': '', 'effective_tbw': '', 'effective_psm': '',
            'effective_width': '', 'effective_height': '', 'effective_cbp': '',
            'effective_cpsm': '', 'effective_csm': '', 'effective_csa': '', 'effective_cld': '',
            'dbp_upload_candidates': '', 'effective_dbp_psm_match': '',
            'cbp_upload_candidates': '', 'evidence_note': '',
        }
        ctx = row['effective_context']
        if name in ('TEX0_1', 'TEX0_2'):
            state = {
                'tbp0': parse_int(reg['tex_tbp0'], 'TEX0 TBP0'),
                'tbw': parse_int(reg['tex_tbw'], 'TEX0 TBW'),
                'psm': reg['tex_psm_name'],
                'width': parse_int(reg['tex_width'], 'TEX0 width'),
                'height': parse_int(reg['tex_height'], 'TEX0 height'),
                'cbp': parse_int(reg['tex_cbp'], 'TEX0 CBP'),
                'cpsm': parse_int(reg['tex_cpsm'], 'TEX0 CPSM'),
                'csm': parse_int(reg['tex_csm'], 'TEX0 CSM'),
                'csa': parse_int(reg['tex_csa'], 'TEX0 CSA'),
                'cld': parse_int(reg['tex_cld'], 'TEX0 CLD'),
                'source_tbp_register': name,
            }
            context_state[ctx] = state
            row['evidence_note'] = 'TEX0 provides base/dimensions and initial PSM/CLUT fields; later TEX2 for this context can replace the PSM/CLUT subset before drawing.'
        elif name in ('TEX2_1', 'TEX2_2'):
            psm_name = reg.get('tex2_psm_name', '')
            if ctx not in context_state:
                row['evidence_note'] = 'TEX2 has PSM/CLUT fields only; no preceding TEX0 context was found in this packet to inherit TBP0/dimensions.'
            else:
                state = dict(context_state[ctx])
                state.update({
                    'psm': psm_name,
                    'cbp': parse_int(reg['tex2_cbp'], 'TEX2 CBP'),
                    'cpsm': parse_int(reg['tex2_cpsm'], 'TEX2 CPSM'),
                    'csm': parse_int(reg['tex2_csm'], 'TEX2 CSM'),
                    'csa': parse_int(reg['tex2_csa'], 'TEX2 CSA'),
                    'cld': parse_int(reg['tex2_cld'], 'TEX2 CLD'),
                    'source_format_register': name,
                })
                context_state[ctx] = state
                row['evidence_note'] = 'Effective candidate combines TBP0/TBW/dimensions from preceding TEX0 and PSM/CLUT fields from this TEX2 write; it is register-state inference, not a runtime material trace.'
        elif name in ('TEX1_1', 'TEX1_2'):
            row['evidence_note'] = 'Texture sampling/level state only; no direct upload lookup is attempted.'
        else:
            row['evidence_note'] = 'This GS register does not carry a decoded texture base in this tool.'

        state = context_state.get(ctx) if ctx else None
        if state:
            for field, out_field in (('tbp0','effective_tbp0'),('tbw','effective_tbw'),('psm','effective_psm'),
                                     ('width','effective_width'),('height','effective_height'),('cbp','effective_cbp'),
                                     ('cpsm','effective_cpsm'),('csm','effective_csm'),('csa','effective_csa'),('cld','effective_cld')):
                row[out_field] = state.get(field, '')
            dbp_matches = by_dbp.get(int(state['tbp0']), [])
            row['dbp_upload_candidates'] = candidate_text(dbp_matches)
            row['effective_dbp_psm_match'] = ('true' if all(u['psm_name'] == state['psm'] for u in dbp_matches) else 'false') if dbp_matches else 'no_match'
            cbp_matches = by_dbp.get(int(state['cbp']), [])
            row['cbp_upload_candidates'] = candidate_text(cbp_matches)
            if cbp_matches:
                row['evidence_note'] += ' CBP matches upload candidate(s); palette/CLUT use remains unconfirmed.'
        out.append(row)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--registers', type=Path, required=True)
    ap.add_argument('--uploads', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--package-region-offset', type=lambda v: int(v, 0), default=0x36A30)
    args = ap.parse_args()
    try:
        rows = cross_reference(read_csv(args.registers), read_csv(args.uploads), args.package_region_offset)
    except (OSError, ValueError) as exc:
        ap.error(str(exc))
    if not rows:
        ap.error('no GS register rows provided')
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open('w', encoding='utf-8-sig', newline='') as fp:
        writer = csv.DictWriter(fp, fieldnames=list(rows[0].keys()))
        writer.writeheader(); writer.writerows(rows)
    print(f'wrote {len(rows)} rows to {args.out}')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
