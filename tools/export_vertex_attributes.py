#!/usr/bin/env python3
"""Export one validated four-stream VIF batch as attributed POINTS (no faces)."""
from __future__ import annotations
import argparse, csv, math, struct
from pathlib import Path

def run(part_b: Path, out_dir: Path, count: int = 60,
        pos_off: int = 0x5E0, nrm_off: int = 0x7D0, color_off: int = 0x9C0, uv_off: int = 0xAC0):
    data=part_b.read_bytes()
    spans=[('position_candidate',pos_off,count*8),('normal_candidate',nrm_off,count*8),('color_candidate',color_off,count*4),('uv_candidate',uv_off,count*8)]
    for name,off,size in spans:
        if off < 0 or size < 0 or off+size > len(data): raise ValueError(f'{name} range 0x{off:X}..0x{off+size:X} outside {part_b} ({len(data)} bytes)')
    positions=[struct.unpack_from('<4h',data,pos_off+i*8) for i in range(count)]
    normals=[struct.unpack_from('<4h',data,nrm_off+i*8) for i in range(count)]
    colors=[tuple(data[color_off+i*4:color_off+i*4+4]) for i in range(count)]
    uvs=[struct.unpack_from('<2f',data,uv_off+i*8) for i in range(count)]
    if not all(math.isfinite(x) and math.isfinite(y) for x,y in uvs): raise ValueError('UV candidate stream has non-finite float')
    normal_lengths=[math.sqrt(sum((v[k]/4096.0)**2 for k in range(3))) for v in normals]
    rows=[]
    for i,(p,n,c,uv) in enumerate(zip(positions,normals,colors,uvs)):
        rows.append({'item_index':i,
          'position_x_s16':p[0],'position_y_s16':p[1],'position_z_s16':p[2],'position_w_s16_raw':p[3],
          'position_x_div4096':f'{p[0]/4096.0:.9g}','position_y_div4096':f'{p[1]/4096.0:.9g}','position_z_div4096':f'{p[2]/4096.0:.9g}',
          'normal_x_s16':n[0],'normal_y_s16':n[1],'normal_z_s16':n[2],'normal_w_s16_raw':n[3],
          'normal_x_div4096':f'{n[0]/4096.0:.9g}','normal_y_div4096':f'{n[1]/4096.0:.9g}','normal_z_div4096':f'{n[2]/4096.0:.9g}',
          'normal_xyz_length_after_div4096':f'{normal_lengths[i]:.9g}',
          'color_r_raw':c[0],'color_g_raw':c[1],'color_b_raw':c[2],'color_a_raw':c[3],
          'uv0_f32_candidate':f'{uv[0]:.9g}','uv1_f32_candidate':f'{uv[1]:.9g}'})
    out_dir.mkdir(parents=True,exist_ok=True)
    csvpath=out_dir/'batch_00_05a0_vertex_attributes.csv'
    with csvpath.open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    ply=out_dir/'batch_00_05a0_vertex_points.ply'
    with ply.open('w',encoding='ascii',newline='\n') as f:
        f.write('ply\nformat ascii 1.0\n')
        f.write('comment MetropolisMania 2 PACKAGE.BIN chunk_00_part_b.bin; batch local start 0x5A0\n')
        f.write('comment vertices only; no faces or triangle topology inferred\n')
        f.write('comment position xyz = raw s16 / 4096 is a candidate scale; raw W retained in CSV\n')
        f.write('comment normal xyz = raw s16 / 4096 strongly suggests normalized direction; semantic mapping not engine-verified\n')
        f.write('comment UV and RGBA are candidate interpretations; payload bytes are preserved in CSV\n')
        f.write(f'element vertex {count}\n')
        for prop in ['property float x','property float y','property float z','property float nx','property float ny','property float nz','property float s','property float t','property int raw_position_w','property int raw_normal_w','property uchar red','property uchar green','property uchar blue','property uchar alpha']:
            f.write(prop+'\n')
        f.write('end_header\n')
        for p,n,c,uv in zip(positions,normals,colors,uvs):
            vals=[p[0]/4096.0,p[1]/4096.0,p[2]/4096.0,n[0]/4096.0,n[1]/4096.0,n[2]/4096.0,uv[0],uv[1],p[3],n[3],*c]
            f.write(' '.join(str(v) for v in vals)+'\n')
    stats={
      'source_file':str(part_b),'source_size_bytes':len(data),'count':count,
      'stream_offsets':{'position_payload':f'0x{pos_off:X}','normal_payload':f'0x{nrm_off:X}','color_payload':f'0x{color_off:X}','uv_payload':f'0x{uv_off:X}'},
      'position_xyz_div4096_minmax':[[min(p[k]/4096.0 for p in positions),max(p[k]/4096.0 for p in positions)] for k in range(3)],
      'normal_xyz_div4096_length_minmax':[min(normal_lengths),max(normal_lengths)],
      'normal_w_values':sorted(set(n[3] for n in normals)),
      'color_tuple_counts':{str(c):colors.count(c) for c in sorted(set(colors))},
      'uv_f32_minmax':[[min(v[k] for v in uvs),max(v[k] for v in uvs)] for k in range(2)],
      'topology':'not inferred; PLY has no face elements'
    }
    import json
    (out_dir/'batch_00_05a0_vertex_attributes_summary.json').write_text(json.dumps(stats,indent=2)+'\n',encoding='utf-8')
    return stats

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--part-b',type=Path,required=True);ap.add_argument('--output-dir',type=Path,required=True)
    ap.add_argument('--count',type=int,default=60);ap.add_argument('--position-offset',type=lambda x:int(x,0),default=0x5E0)
    ap.add_argument('--normal-offset',type=lambda x:int(x,0),default=0x7D0);ap.add_argument('--color-offset',type=lambda x:int(x,0),default=0x9C0)
    ap.add_argument('--uv-offset',type=lambda x:int(x,0),default=0xAC0)
    a=ap.parse_args();s=run(a.part_b,a.output_dir,a.count,a.position_offset,a.normal_offset,a.color_offset,a.uv_offset)
    print(f"Exported {s['count']} attributed points; no faces created")
if __name__=='__main__': main()
