#!/usr/bin/env python3
import argparse, re
from pathlib import Path

DRIVER_TMPL = r'''// driver_{stem}.c — KLEE driver (single TU)
// Generated for instrumented_{stem}.c

#include "klee/klee.h"

// Pull in the full instrumented TU (main_single + adapter + source)
#include "{instr_basename}"

// Declare Juliet bad endpoint (provided by included TU)
int {stem}_bad(void);

static void make_symbolic_int(const char* name, int* ptr) {{
  klee_make_symbolic(ptr, sizeof(*ptr), name);
}}

int main(void) {{
  // Make requested ints symbolic
{sym_inits}

{bound_block}
  // Call the Juliet bad function (entrypoint lives in the included TU)
  (void){stem}_bad();
  return 0;
}}
'''

def parse_range(s):
    """
    Accept forms:
      '-100<=x<=100'
      '-100<=*<=100'
      '-100..100'
      '-100,100'
    Returns (lo,hi) as ints.
    """
    s = s.strip()
    m = re.match(r'^\s*(-?\d+)\s*<=\s*.*?\s*<=\s*(-?\d+)\s*$', s)
    if m:
        return int(m.group(1)), int(m.group(2))
    m = re.match(r'^\s*(-?\d+)\s*\.\.\s*(-?\d+)\s*$', s)
    if m:
        return int(m.group(1)), int(m.group(2))
    m = re.match(r'^\s*(-?\d+)\s*,\s*(-?\d+)\s*$', s)
    if m:
        return int(m.group(1)), int(m.group(2))
    raise ValueError(f"Unrecognized bound format: {s!r}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--stem', required=True, help='Juliet stem, e.g., CWE190_Integer_Overflow__int_fscanf_multiply_01')
    ap.add_argument('--instrumented', required=True, help='Path to instrumented_*.c (or its directory)')
    ap.add_argument('--out', required=True, help='Output directory for the driver .c')
    ap.add_argument('--sym-int', nargs='*', default=[], help='Names of int variables to make symbolic (e.g., data size count)')
    ap.add_argument('--bound', default=None, help="Optional aggregate bounds, e.g. '-100<=x<=100' or '-100..100' or '-100,100'")
    ap.add_argument('--lo', type=int, default=None, help='Optional lower bound (alternative to --bound)')
    ap.add_argument('--hi', type=int, default=None, help='Optional upper bound (alternative to --bound)')
    args = ap.parse_args()

    out_dir = Path(args.out); out_dir.mkdir(parents=True, exist_ok=True)

    instr_path = Path(args.instrumented)
    if instr_path.is_dir():
        # Expect standard name inside the directory
        instr_path = instr_path / f"instrumented_{args.stem}.c"
    if not instr_path.exists():
        raise SystemExit(f"[err] instrumented file not found: {instr_path}")

    # Resolve bounds
    lo = hi = None
    if args.bound:
        lo, hi = parse_range(args.bound)
    elif args.lo is not None or args.hi is not None:
        if args.lo is None or args.hi is None:
            raise SystemExit("[err] please provide both --lo and --hi if using that style")
        lo, hi = args.lo, args.hi

    # Build code for symbolic vars
    sym_lines = []
    for v in args.sym_int:
        sym_lines.append(f'  int {v}; make_symbolic_int("{v}", &{v});')

    sym_inits = "\n".join(sym_lines) if sym_lines else "  /* no symbolic ints requested */"

    if lo is not None and hi is not None and sym_lines:
        # Apply same bounds to each symbolic int
        bound_checks = "\n".join([f'  klee_assume({v} >= {lo} && {v} <= {hi});' for v in args.sym_int])
        bound_block = f"{bound_checks}\n"
    else:
        bound_block = "  /* no bounds applied */\n"

    driver_code = DRIVER_TMPL.format(
        stem=args.stem,
        instr_basename=instr_path.name,
        sym_inits=sym_inits,
        bound_block=bound_block
    )

    out_c = out_dir / f"driver_{args.stem}.c"
    out_c.write_text(driver_code)
    print(f"[ok] wrote {out_c}")

if __name__ == '__main__':
    main()
