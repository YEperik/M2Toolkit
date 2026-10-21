#!/usr/bin/env python3
"""Render cautious visual previews from raw PS2 GS image-transfer payloads.

This helper does not modify source game files. PSMT4/PSMT8 previews show palette
indices as grayscale because the game's CLUT/palette mapping is not yet recovered.
"""
from __future__ import annotations

import argparse
import csv
import pathlib
import sys
from collections import Counter
from PIL import Image, ImageDraw


def read_catalog(path: pathlib.Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def make_preview(row: dict[str, str], payload: bytes) -> Image.Image:
    width = int(row["width"])
    height = int(row["height"])
    psm = row["psm_name"]
    expected = width * height * int(row["bits_per_pixel"]) // 8
    if len(payload) != expected or len(payload) != int(row["payload_size_bytes"]):
        raise ValueError(
            f"Payload length mismatch for texture {row['texture_index']}: "
            f"{len(payload)} bytes, expected {expected}"
        )

    if psm == "PSMCT32":
        # Candidate RGBA interpretation: PS2 GS PSMCT32 uses 32-bit RGBA-like channels.
        return Image.frombytes("RGBA", (width, height), payload)
    if psm == "PSMT8":
        # Palette is unknown; display 8-bit texel indices as grayscale only.
        return Image.frombytes("L", (width, height), payload)
    if psm == "PSMT4":
        # Hypothesis: first pixel is in the low nibble, second pixel in the high nibble.
        indices = bytearray(width * height)
        out = 0
        for value in payload:
            indices[out] = (value & 0x0F) * 17
            indices[out + 1] = ((value >> 4) & 0x0F) * 17
            out += 2
        if out != len(indices):
            raise ValueError(f"PSMT4 pixel count mismatch for texture {row['texture_index']}")
        return Image.frombytes("L", (width, height), bytes(indices))
    raise ValueError(f"Unsupported PSM {psm!r} in texture {row['texture_index']}")


def make_contact_sheets(
    images: list[tuple[dict[str, str], pathlib.Path]], output_dir: pathlib.Path,
    per_sheet: int = 96, columns: int = 8,
) -> int:
    contact_dir = output_dir / "contact_sheets"
    contact_dir.mkdir()
    cell_w, cell_h = 112, 94
    rows_per_sheet = per_sheet // columns
    count = 0

    for sheet_index, start in enumerate(range(0, len(images), per_sheet)):
        batch = images[start : start + per_sheet]
        rows = (len(batch) + columns - 1) // columns
        sheet = Image.new("RGB", (columns * cell_w, rows * cell_h), (30, 30, 30))
        draw = ImageDraw.Draw(sheet)
        for local_index, (row, image_path) in enumerate(batch):
            source = Image.open(image_path).convert("RGBA")
            source.thumbnail((80, 62), Image.Resampling.NEAREST)
            col = local_index % columns
            line = local_index // columns
            x = col * cell_w + (cell_w - source.width) // 2
            y = line * cell_h + 2
            # Composite on a neutral background for preview only; per-texture PNG remains intact.
            background = Image.new("RGBA", source.size, (72, 72, 72, 255))
            background.alpha_composite(source)
            sheet.paste(background.convert("RGB"), (x, y))
            label = (
                f"#{int(row['texture_index']):04d} C{int(row['chunk_index']):02d}\n"
                f"{row['width']}x{row['height']} {row['psm_name']}"
            )
            draw.multiline_text((col * cell_w + 4, line * cell_h + 66), label, fill=(235, 235, 235), spacing=1)
        sheet_path = contact_dir / f"contact_{sheet_index:02d}.png"
        sheet.save(sheet_path, optimize=True)
        count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("analysis_dir", type=pathlib.Path, help="output from datase_package_probe")
    parser.add_argument("output_dir", type=pathlib.Path, help="new or empty preview output directory")
    args = parser.parse_args()

    catalog_path = args.analysis_dir / "texture_uploads.csv"
    payload_dir = args.analysis_dir / "texture_payloads"
    if not catalog_path.is_file() or not payload_dir.is_dir():
        print("ERROR: texture_uploads.csv or texture_payloads/ not found in analysis directory", file=sys.stderr)
        return 2
    if args.output_dir.exists():
        if not args.output_dir.is_dir() or any(args.output_dir.iterdir()):
            print("ERROR: output directory must be new or empty", file=sys.stderr)
            return 2
    else:
        args.output_dir.mkdir(parents=True)

    rows = read_catalog(catalog_path)
    previews_dir = args.output_dir / "previews"
    previews_dir.mkdir()
    images: list[tuple[dict[str, str], pathlib.Path]] = []
    counts: Counter[str] = Counter()

    try:
        for row in rows:
            payload_path = payload_dir / row["payload_file"]
            payload = payload_path.read_bytes()
            image = make_preview(row, payload)
            preview_path = previews_dir / (pathlib.Path(row["payload_file"]).stem + ".png")
            image.save(preview_path, optimize=True)
            images.append((row, preview_path))
            counts[row["psm_name"]] += 1
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    contact_count = make_contact_sheets(images, args.output_dir)
    total_bytes = sum((payload_dir / row["payload_file"]).stat().st_size for row in rows)
    report = (
        "DATASE — laporan preview image-transfer\n"
        "======================================\n\n"
        f"Jumlah payload: {len(rows)}\n"
        f"Jumlah byte payload: {total_bytes}\n"
        f"PNG preview: {len(images)}\n"
        f"Contact sheet: {contact_count}\n\n"
        "Format:\n"
        f"  PSMT4: {counts['PSMT4']} (index 4-bit ditampilkan grayscale; asumsi pixel pertama = low nibble)\n"
        f"  PSMT8: {counts['PSMT8']} (index 8-bit ditampilkan grayscale)\n"
        f"  PSMCT32: {counts['PSMCT32']} (byte ditampilkan sebagai RGBA kandidat)\n\n"
        "Batas interpretasi:\n"
        "  * PSMT4/PSMT8 belum memiliki CLUT/palette game yang terhubung; grayscale hanya menunjukkan nilai index, bukan warna final game.\n"
        "  * Urutan nibble PSMT4 dan interpretasi channel/alpha PSMCT32 masih perlu dibandingkan dengan tampilan game atau data palette.\n"
        "  * Preview bukan bukti bahwa texture/material sudah terhubung ke model tertentu.\n"
        "  * File PNG preview terpisah dari payload .bin mentah yang diekstrak byte-per-byte.\n"
    )
    (args.output_dir / "preview_report.txt").write_text(report, encoding="utf-8")
    print(f"Rendered {len(images)} PNG previews and {contact_count} contact sheets.")
    print(f"Output: {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
