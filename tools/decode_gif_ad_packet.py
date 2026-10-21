#!/usr/bin/env python3
"""Decode a bounded PS2 GIF packed A+D packet for inspection only."""
from __future__ import annotations
import argparse, csv, json, struct
from pathlib import Path
from typing import Any

GS_REG_NAMES = {
    0x00:'PRIM',0x01:'RGBAQ',0x02:'ST',0x03:'UV',0x04:'XYZF2',0x05:'XYZ2',
    0x06:'TEX0_1',0x07:'TEX0_2',0x08:'CLAMP_1',0x09:'CLAMP_2',0x0A:'FOG',
    0x0C:'XYZF3',0x0D:'XYZ3',0x0E:'A+D',0x0F:'NOP',
    0x14:'TEX1_1',0x15:'TEX1_2',0x16:'TEX2_1',0x17:'TEX2_2',
    0x18:'XYOFFSET_1',0x19:'XYOFFSET_2',0x1A:'PRMODECONT',0x1B:'PRMODE',
    0x1C:'TEXCLUT',0x22:'SCANMSK',0x34:'MIPTBP1_1',0x35:'MIPTBP1_2',
    0x36:'MIPTBP2_1',0x37:'MIPTBP2_2',0x3B:'TEXA',0x3D:'FOGCOL',
    0x40:'TEXFLUSH',0x42:'SCISSOR_1',0x43:'SCISSOR_2',0x47:'ALPHA_1',0x48:'ALPHA_2',
}
PSM_NAMES = {0x00:'PSMCT32',0x01:'PSMCT24',0x02:'PSMCT16',0x0A:'PSMCT16S',0x13:'PSMT8',0x14:'PSMT4',0x1B:'PSMT8H',0x24:'PSMT4HL',0x2C:'PSMT4HH'}


def sign_extend(v: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (v ^ sign) - sign


def decode_tex0(value: int) -> dict[str, Any]:
    take = lambda shift, width: (value >> shift) & ((1 << width) - 1)
    psm = take(20, 6)
    return {
        'tbp0': take(0, 14), 'tbw': take(14, 6), 'psm': psm,
        'psm_name': PSM_NAMES.get(psm, f'UNKNOWN_0x{psm:02X}'),
        'tw_log2': take(26, 4), 'th_log2': take(30, 4),
        'width': 1 << take(26, 4), 'height': 1 << take(30, 4),
        'tcc': take(34, 1), 'tfx': take(35, 2),
        'cbp': take(37, 14), 'cpsm': take(51, 4),
        'csm': take(55, 1), 'csa': take(56, 5), 'cld': take(61, 3),
    }


def decode_tex1(value: int) -> dict[str, Any]:
    return {
        'lcm': value & 1,
        'mxl': (value >> 2) & 7,
        'mmag': (value >> 5) & 1,
        'mmin': (value >> 6) & 7,
        'mtba': (value >> 9) & 1,
        'l': (value >> 19) & 0x3,
        'k_signed': sign_extend((value >> 32) & 0xfff, 12),
    }


def decode_tex2(value: int) -> dict[str, Any]:
    """Decode only fields defined by the GS TEX2 register; low 20 bits are reserved."""
    take = lambda shift, width: (value >> shift) & ((1 << width) - 1)
    psm = take(20, 6)
    return {
        'psm': psm,
        'psm_name': PSM_NAMES.get(psm, f'UNKNOWN_0x{psm:02X}'),
        'cbp': take(37, 14), 'cpsm': take(51, 4), 'csm': take(55, 1),
        'csa': take(56, 5), 'cld': take(61, 3),
    }


def decode_packet(packet: bytes, source_offset: int = 0) -> dict[str, Any]:
    if len(packet) < 16 or len(packet) % 16:
        raise ValueError('GIF packet length must be a positive multiple of 16 bytes')
    tag_lo, tag_hi = struct.unpack_from('<QQ', packet, 0)
    nloop = tag_lo & 0x7fff
    eop = (tag_lo >> 15) & 1
    pre = (tag_lo >> 46) & 1
    prim = (tag_lo >> 47) & 0x7ff
    flg = (tag_lo >> 58) & 0x3
    nreg_raw = (tag_lo >> 60) & 0xf
    nreg = nreg_raw or 16
    if flg != 0:
        raise ValueError(f'only PACKED GIF mode (FLG=0) is supported, got FLG={flg}')
    if nloop == 0 or nloop > 4096:
        raise ValueError(f'unreasonable GIF NLOOP: {nloop}')
    expected = 16 * (1 + nloop * nreg)
    if expected != len(packet):
        raise ValueError(f'GIF tag requires {expected} bytes for NLOOP={nloop}, NREG={nreg}; got {len(packet)}')
    regs = [(tag_hi >> (4 * i)) & 0xf for i in range(nreg)]
    if not regs:
        raise ValueError('GIF tag has empty register list')
    rows: list[dict[str, Any]] = []
    idx = 0
    for loop_index in range(nloop):
        for reg_index, reg_id in enumerate(regs):
            off = 16 * (1 + idx)
            qlo, qhi = struct.unpack_from('<QQ', packet, off)
            reg_name = GS_REG_NAMES.get(reg_id, f'GSREG_0x{reg_id:02X}')
            row: dict[str, Any] = {
                'loop_index': loop_index, 'register_index': reg_index,
                'packet_offset_hex': f'0x{source_offset + off:X}',
                'reg_id_hex': f'0x{reg_id:02X}', 'reg_name': reg_name,
                'data_u64_hex': f'0x{qlo:016X}', 'addr_u64_hex': f'0x{qhi:016X}',
            }
            if reg_id == 0x0e:
                gs_addr = qhi & 0xff
                row['actual_gs_address_hex'] = f'0x{gs_addr:02X}'
                row['actual_gs_register'] = GS_REG_NAMES.get(gs_addr, f'GSREG_0x{gs_addr:02X}')
                row['actual_gs_value_hex'] = f'0x{qlo:016X}'
                if gs_addr in (0x06, 0x07):
                    tex = decode_tex0(qlo)
                    row.update({f'tex_{k}': v for k,v in tex.items()})
                elif gs_addr in (0x16, 0x17):
                    tex2 = decode_tex2(qlo)
                    row.update({f'tex2_{k}': v for k,v in tex2.items()})
                elif gs_addr in (0x14, 0x15):
                    row.update({f'tex1_{k}': v for k,v in decode_tex1(qlo).items()})
            rows.append(row)
            idx += 1
    return {
        'source_offset': source_offset,
        'packet_bytes': len(packet),
        'gif_tag_low_u64_hex': f'0x{tag_lo:016X}',
        'gif_tag_registers_u64_hex': f'0x{tag_hi:016X}',
        'nloop': nloop, 'eop': eop, 'pre': pre, 'prim': prim,
        'flg': flg, 'nreg_raw': nreg_raw, 'nreg': nreg,
        'register_descriptor_ids': [f'0x{x:X}' for x in regs],
        'rows': rows,
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open('w', newline='', encoding='utf-8-sig') as fp:
        wr = csv.DictWriter(fp, fieldnames=fields); wr.writeheader(); wr.writerows(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input', type=Path, required=True, help='Raw input region, e.g. chunk_00_part_b.bin')
    ap.add_argument('--offset', type=lambda x: int(x, 0), required=True, help='GIF packet start offset in input')
    ap.add_argument('--qwc', type=int, required=True, help='Exact GIF packet length in quadwords, including GIFtag')
    ap.add_argument('--out-dir', type=Path, required=True)
    args = ap.parse_args()
    data = args.input.read_bytes()
    if args.qwc < 1 or args.qwc > 4096:
        raise SystemExit('QWC outside safe bounds')
    end = args.offset + args.qwc * 16
    if args.offset < 0 or end > len(data):
        raise SystemExit('packet range outside input bounds')
    packet = data[args.offset:end]
    result = decode_packet(packet, args.offset)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / 'pre_batch_gif_packet_summary.json').write_text(json.dumps({k:v for k,v in result.items() if k!='rows'}, indent=2), encoding='utf-8')
    write_csv(args.out_dir / 'pre_batch_gif_ad_registers.csv', result['rows'])
    print(json.dumps({k:v for k,v in result.items() if k!='rows'}, indent=2))
    for row in result['rows']:
        print(f"{row.get('actual_gs_register', row['reg_name'])}: {row.get('actual_gs_value_hex', row['data_u64_hex'])}")
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
