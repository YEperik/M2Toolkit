#!/usr/bin/env python3
import importlib.util
import struct
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'tools' / 'disassemble_vu.py'
spec = importlib.util.spec_from_file_location('disassemble_vu', SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# Known upper NOP encoding used as filler in the extracted programs.
assert mod.decode_upper(0x000002FF, 0x00000000)[0] == 'nop'
# XGKICK sub-op encoding: the extraction reference maps extended lower op 0x6C.
# Assemble fields into a lower word with the special sub-op in bits 4..10 and low bits.
xgkick = 0x80000000 | ((0x6C & 0x7C) << 4) | (0x6C & 0x3) | (3 << 11)
text, cat, is_xg = mod.decode_lower(xgkick, 0)
assert cat == 'gs_output' and is_xg and text.startswith('xgkick '), (hex(xgkick), text, cat)
# E bit must be preserved and recognized without misclassifying instruction as LOI.
text, fl, ebit = mod.decode_upper((1 << 30) | 0x2FF, 0)
assert ebit and 'E' in fl and text == 'nop'
# I-bit: lower word is an immediate to LOI, not a lower instruction.
text, cat, is_xg = mod.decode_lower(xgkick, 0x80000000)
assert cat == 'immediate' and not is_xg
text, _, _ = mod.decode_upper(0x80000000, 0x3F800000)
assert text.startswith('loi 0x3F800000')
# Truncated/nonaligned microprograms are rejected.
try:
    mod.disassemble_program(b'1234567','TEST','test',0,'bad.bin')
except ValueError:
    pass
else:
    raise AssertionError('non-multiple-of-eight program should be rejected')
# Relative VU branches use the delay-slot instruction (PC+1) as the base.
assert mod.relative_branch_target(0x420F05E6, 0x0119) == 0x0700
assert mod.relative_branch_target(0x520307BA, 0x011E) == 0x00D9
assert mod.relative_branch_target(0x400007A0, 0x0123) == 0x00C4

print('VU decoder synthetic tests: PASS')
