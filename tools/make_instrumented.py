#!/usr/bin/env python3
import argparse, re
from pathlib import Path

MAIN_RE = re.compile(r'\bint\s+main\s*\([^)]*\)\s*\{', re.M)

def strip_main(fn: Path) -> str:
    s = fn.read_text()
    m = MAIN_RE.search(s)
    if not m:
        return s
    i = m.end()
    depth = 1
    while i < len(s) and depth > 0:
        if s[i] == '{':
            depth += 1
        elif s[i] == '}':
            depth -= 1
        i += 1
    return s[:m.start()] + "\n/* (main removed by make_instrumented.py) */\n" + s[i:]

def main():
    ap = argparse.ArgumentParser(
        description="Amalgamate Juliet source+adapter+main into a single instrumented C file (no main)."
    )
    ap.add_argument("--source",  required=True, help="path to Juliet source.c (contains <stem>_bad)")
    ap.add_argument("--adapter", required=True, help="path to adapter.c")
    ap.add_argument("--main",    required=True, help="path to main_single.c (its main() will be stripped)")
    ap.add_argument("--out",     required=True, help="output file OR directory")
    ap.add_argument("--stem",    default=None, help="optional explicit stem for banners / naming")
    args = ap.parse_args()

    src = Path(args.source)
    adp = Path(args.adapter)
    man = Path(args.main)
    out = Path(args.out)

    stem = (args.stem or src.stem)

    # Resolve output path: accept file OR directory
    if out.is_dir() or (not out.suffix and not out.exists()):
        # treat as directory; create and use default filename
        out.mkdir(parents=True, exist_ok=True)
        out = out / f"instrumented_{stem}.c"
    else:
        out.parent.mkdir(parents=True, exist_ok=True)

    src_text = src.read_text()
    adp_text = adp.read_text()
    main_no_main = strip_main(man)

    def banner(name, path): return f"\n\n/* ==== BEGIN {name}: {path} (amalgamated) ================= */\n"
    def ender(name):        return f"\n/* ==== END {name} ===================================== */\n"

    parts = []
    parts.append(f"/* instrumented file generated for {stem} */\n")
    parts.append('#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include "state.h"\n')
    parts.append(banner("ADAPTER", adp))
    parts.append(adp_text)
    parts.append(ender("ADAPTER"))
    parts.append(banner("MAIN_SINGLE (no main())", man))
    parts.append(main_no_main)
    parts.append(ender("MAIN_SINGLE"))
    parts.append(banner("JULIET SOURCE", src))
    parts.append(src_text)
    parts.append(ender("JULIET SOURCE"))

    out.write_text("".join(parts))
    print(f"[ok] wrote {out}")

if __name__ == "__main__":
    main()
