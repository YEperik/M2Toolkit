# DATASE read-only text probe

A small C++17 forensic tool for the supplied `WORDS.BIN` and `WORDSEVE.BIN` samples. It is deliberately **read-only** and does not attempt to rebuild game files.

## What is confirmed by the supplied samples

### Candidate two-block chain

- `WORDS.BIN`: the first little-endian `uint32` is `0x91AC`; the bytes at file offset `0x91AC` start another header-like structure whose first `uint32` is `0` and whose relative section offsets match the first block's offsets.
- `WORDSEVE.BIN`: the first little-endian `uint32` is `0x4280`; the bytes at file offset `0x4280` start another header-like structure whose first `uint32` is `0` and whose relative section offsets are internally ordered and in range.
- This strongly supports a two-block/linked-block interpretation for these two exact samples. The first dword's semantic role is still a candidate pointer, since the game code that consumes the files is not available.

### `WORDSEVE.BIN`, first block

- The candidate offset table spans relative offsets `0x440..0x4C8`, exactly 136 bytes or 68 little-endian `uint16` values.
- Four raw bytes `10 08 3D 08` appear at `0x4C8`; strings begin at `0x4CC`.
- Interpreting the 68 values as relative offsets from `0x4CC` validates all entries as printable ASCII NUL-terminated strings on string boundaries. There are 66 distinct relative offsets and 21 distinct string contents across the 68 references.
- The second block has a candidate table at relative offsets `0xF8..0x114` (14 `uint16` values). It does **not** pass the same string-offset validation, so this table is exported raw without semantic labels.

### `WORDS.BIN`, both blocks

- Each block has a candidate raw table at relative offsets `0x338..0x4F8`, exactly 448 bytes or 224 little-endian `uint16` values.
- The first three values are `[0, 221, 0]` in block 0 and `[1, 221, 0]` in block 1. Indices `1..107` match between blocks; indices `0` and `108..223` differ. This is only a measured comparison; it does not prove what these values mean.
- The data region begins with `46 0C 00 00 3F 00` in block 0 and `C5 0B 00 00 3F 00` in block 1. Printable ASCII text begins six bytes after each region start. The six-byte prefix remains uninterpreted.

These findings apply to the exact supplied samples, not every revision of a game with similarly named files.

## Build and test

Requirements: CMake 3.16+ and a C++17 compiler. Python 3 is optional for integration testing.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DDATASE_BIN_DIR=/path/to/DATASE/BIN
cmake --build build --config Release
ctest --test-dir build --output-on-failure
```

`DATASE_BIN_DIR` is optional for compiling the tool, but required to register the sample-based integration test. Point it to the directory containing the exact `WORDS.BIN` and `WORDSEVE.BIN` files you want to test.

## Run

```sh
./build/datase_probe /path/to/DATASE/BIN ./probe-output
```

The tool writes:

- `docs/block_chain.csv` — measured block bases, first-word pointer candidates, candidate byte ranges and candidate table ranges.
- `docs/WORDSEVE_offsets.csv` — the 68 verified string references from block 0.
- `docs/WORDSEVE_tables_raw_u16.csv` — raw 16-bit values from candidate tables in both `WORDSEVE` blocks.
- `WORDS_u16_region.csv` — raw 16-bit values and source byte offsets from both `WORDS` blocks.
- `docs/probe_report.txt` — concise findings and limitations.

Use a separate output directory to keep source assets untouched. The reader enforces file-size limits, range/overflow checks, forward-only block pointers, table-size divisibility, NUL termination, printable ASCII, and visible string boundaries. It fails closed if the observed layout does not fit.
