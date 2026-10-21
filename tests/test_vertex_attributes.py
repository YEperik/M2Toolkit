#!/usr/bin/env python3
import sys, tempfile, struct
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import export_vertex_attributes
with tempfile.TemporaryDirectory() as td:
    p=Path(td)/'partb.bin'
    b=bytearray(0xB0)
    # count 2; all 4 streams exactly two items at offsets 0x10, 0x20, 0x30, 0x40
    for i in range(2):
        struct.pack_into('<4h',b,0x10+i*8,4096*i,0,4096,0)
        struct.pack_into('<4h',b,0x20+i*8,0,0,4096,4096)
        b[0x30+i*4:0x34+i*4]=bytes((1,2,3,255))
        struct.pack_into('<2f',b,0x40+i*8,float(i),0.5)
    p.write_bytes(b)
    stats=export_vertex_attributes.run(p,Path(td)/'out',2,0x10,0x20,0x30,0x40)
    assert stats['count']==2
    ply=(Path(td)/'out'/'batch_00_05a0_vertex_points.ply').read_text()
    assert 'element vertex 2' in ply and 'element face' not in ply
    assert len((Path(td)/'out'/'batch_00_05a0_vertex_attributes.csv').read_text().splitlines())==3
print('Vertex attribute exporter synthetic: PASS')
