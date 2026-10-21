#!/usr/bin/env python3
"""Extract the 24 descriptor Part B regions and global Part B for VIF scanning."""
from __future__ import annotations
import argparse
import hashlib
import json
import pathlib
import sys

# Reuse the strict descriptor parser rather than reimplementing the layout.
TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from map_package_assets import parse_descriptors  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_bin", type=pathlib.Path, help="extracted PACKAGE.BIN")
    parser.add_argument("output_dir", type=pathlib.Path, help="new or empty directory for scanner input files")
    args = parser.parse_args()
    try:
        if args.output_dir.exists() and (not args.output_dir.is_dir() or any(args.output_dir.iterdir())):
            raise ValueError("output directory must be new or empty")
        package = args.package_bin.read_bytes()
        global_desc, descs, _ = parse_descriptors(package)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        manifest = []
        ranges = [(24, global_desc, "GLOBAL_PART_B_PSEUDO_INDEX_24")] + [
            (int(d.index), d, f"CHUNK_{int(d.index):02d}_PART_B") for d in descs
        ]
        for index, desc, label in ranges:
            start, end = desc.part_b_start, desc.end
            name = f"chunk_{index:02d}_part_b.bin"
            chunk = package[start:end]
            if len(chunk) != desc.size_b:
                raise ValueError(f"internal range/size mismatch for {label}")
            (args.output_dir / name).write_bytes(chunk)
            manifest.append({
                "scanner_index": index, "label": label, "file": name,
                "package_start_hex": f"0x{start:08X}", "package_end_exclusive_hex": f"0x{end:08X}",
                "size_bytes": len(chunk), "sha256": hashlib.sha256(chunk).hexdigest(),
            })
        report = {
            "package_path_name_only": args.package_bin.name,
            "package_size_bytes": len(package),
            "package_sha256": hashlib.sha256(package).hexdigest(),
            "regular_part_b_count": len(descs), "global_part_b_scanner_index": 24,
            "files": manifest,
            "note": "Index 24 is analysis-only for global Part B; it is not a 25th game object descriptor.",
        }
        (args.output_dir / "scan_input_manifest.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"PASS: extracted {len(descs)} regular Part B regions and one global Part B region")
        print(f"Output: {args.output_dir.resolve()}")
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
