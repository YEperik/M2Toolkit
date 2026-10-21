#!/usr/bin/env python3
"""Synthetic tests for the bounded GIF packed A+D decoder."""
from __future__ import annotations
import importlib.util
import struct
import sys
from pathlib import Path

SCRIPT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / 'tools' / 'decode_gif_ad_packet.py'
spec = importlib.util.spec_from_file_location('decode_gif_ad_packet', SCRIPT)
mod = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(mod)


def tex0(tbp0: int, tbw: int, psm: int, tw: int, th: int, tcc: int, tfx: int,
          cbp: int, cpsm: int, csm: int, csa: int, cld: int) -> int:
    return (tbp0 | (tbw << 14) | (psm << 20) | (tw << 26) | (th << 30) |
            (tcc << 34) | (tfx << 35) | (cbp << 37) | (cpsm << 51) |
            (csm << 55) | (csa << 56) | (cld << 61))


def make_packet(flg: int = 0) -> bytes:
    # GIFtag: NLOOP=3, EOP=1, PRE=0, packed mode, NREG=1, descriptor A+D.
    tag_lo = 3 | (1 << 15) | (flg << 58) | (1 << 60)
    tag_hi = 0xE
    out = bytearray(struct.pack('<QQ', tag_lo, tag_hi))
    values = [
        (0x261, 0x14),
        (tex0(9277, 2, 0x13, 6, 5, 1, 0, 9320, 0, 0, 0, 4), 0x06),
        (tex0(0, 0, 0x14, 0, 0, 0, 0, 9320, 0, 0, 13, 0), 0x16),
    ]
    for value, addr in values:
        out += struct.pack('<QQ', value, addr)
    return bytes(out)


packet = make_packet()
decoded = mod.decode_packet(packet, 0x560)
assert decoded['packet_bytes'] == 64
assert (decoded['nloop'], decoded['eop'], decoded['pre'], decoded['flg'], decoded['nreg']) == (3, 1, 0, 0, 1)
rows = decoded['rows']
assert [r['actual_gs_register'] for r in rows] == ['TEX1_1', 'TEX0_1', 'TEX2_1']
assert rows[0]['actual_gs_value_hex'] == '0x0000000000000261'
assert (rows[1]['tex_tbp0'], rows[1]['tex_tbw'], rows[1]['tex_psm_name'], rows[1]['tex_width'], rows[1]['tex_height']) == (9277, 2, 'PSMT8', 64, 32)
assert (rows[1]['tex_cbp'], rows[1]['tex_cpsm'], rows[1]['tex_cld']) == (9320, 0, 4)
assert (rows[2]['tex2_psm_name'], rows[2]['tex2_cbp'], rows[2]['tex2_csa'], rows[2]['tex2_cld']) == ('PSMT4', 9320, 13, 0)
assert 'tex_tbp0' not in rows[2] and 'tex_width' not in rows[2]  # TEX2 reserved bits are not TEX0 fields.
assert mod.decode_tex1(0x261)['l'] == 0

for bad_packet in (packet[:-16], packet + bytes(16)):
    try:
        mod.decode_packet(bad_packet)
    except ValueError:
        pass
    else:
        raise AssertionError('incorrect packet length was accepted')
try:
    mod.decode_packet(make_packet(flg=1))
except ValueError:
    pass
else:
    raise AssertionError('unsupported IMAGE mode was accepted')
print('GIF A+D decoder synthetic: PASS (GIFtag bounds, TEX1/TEX0/TEX2 fields, bad size, unsupported FLG)')
