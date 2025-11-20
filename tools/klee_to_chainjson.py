#!/usr/bin/env python3
import argparse, json, re
from pathlib import Path

# -------- regexes ----------
SEG_RE = re.compile(r"\bcb_region(?:_new)?\s*\(\s*(SEG_[A-Z_]+)", re.M)
ACT_RE = re.compile(r"\bcb_effect_push\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*(ACT_[A-Z_]+)", re.M)
KQUERY_PRE_RE = re.compile(r"\(query\s*\[\s*(.*?)\s*\]\s*false\)", re.S)
KQUERY_PRE_ALT = re.compile(r"\(query\s*\[\s*(.*?)\s*\]\s*\(Eq false.*?\)\s*\)", re.S)

def infer_effect_from_main(main_path: Path):
    txt = main_path.read_text(errors="ignore")
    seg = act = None
    mseg = SEG_RE.search(txt)
    mact = ACT_RE.search(txt)
    if mseg: seg = mseg.group(1).replace("SEG_", "", 1)
    if mact: act = mact.group(1).replace("ACT_", "", 1)
    return (seg, act)

def find_assert_errs(klee_dir: Path):
    return sorted(klee_dir.glob("test*.assert.err"))

def parse_assert_err(err_path: Path):
    tid = err_path.stem.split(".")[0]
    txt = err_path.read_text(errors="ignore")
    m = re.search(r"\bat\s+([^\s:]+):(\d+)", txt)
    if not m:
        m = re.search(r"file:\s*([^\s,]+)\s*,\s*line:\s*(\d+)", txt, flags=re.I)
    file_name, line_no = (None, None)
    if m:
        file_name, line_no = m.group(1), int(m.group(2))
    return tid, file_name, line_no

def parse_source_for_assert_line(src_path: Path):
    patt = re.compile(r"\b(klee_assert|CB_ASSERT)\s*\(")
    with src_path.open("r", errors="ignore") as f:
        for i, line in enumerate(f, 1):
            if patt.search(line):
                return i
    return None

def read_line(src_path: Path, line_no: int):
    try:
        lines = src_path.read_text(errors="ignore").splitlines()
        if 1 <= line_no <= len(lines):
            return lines[line_no-1].rstrip()
    except Exception:
        pass
    return None

def extract_assert_expr(src_path: Path, line_no: int):
    text = src_path.read_text(errors="ignore")
    lines = text.splitlines()
    target = None
    if 1 <= (line_no or 0) <= len(lines):
        target = lines[line_no-1]

    def grab(line):
        m = re.search(r"\b(?:klee_assert|CB_ASSERT)\s*\(\s*(.*?)\s*\)\s*;", line)
        return m.group(1) if m else None

    expr = grab(target) if target else None
    if expr: return expr
    for ln in lines:
        expr = grab(ln)
        if expr: return expr
    return None

def parse_kquery_precondition(kq_path: Path):
    try:
        txt = kq_path.read_text(errors="ignore")
    except Exception:
        return None
    m = KQUERY_PRE_RE.search(txt) or KQUERY_PRE_ALT.search(txt)
    if not m:
        return None
    body = m.group(1).strip()
    body = re.sub(r"\s+", " ", body)
    return f"(query [{body}] false)"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--klee-dir", help="path to klee-out or klee-last")
    ap.add_argument("--step", required=True, help="scenario step / stem name")
    ap.add_argument("--vars", nargs="*", default=[], help="symbolic variable names of interest")
    ap.add_argument("--main", required=True, help="path to main_single.c (for effect inference)")
    ap.add_argument("--source", required=True, help="path to instrumented source (for location/target/assert)")
    ap.add_argument("--type", default="INT_OVERFLOW", help='vuln type (default "INT_OVERFLOW")')
    ap.add_argument("--cwe", type=int, default=190, help="CWE id (default 190)")
    ap.add_argument("--out", required=True, help="output JSON path")
    args = ap.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    seg, act = infer_effect_from_main(Path(args.main))
    src_path = Path(args.source)

    klee_dir = Path(args.klee_dir) if args.klee_dir else None
    err_files = find_assert_errs(klee_dir) if (klee_dir and klee_dir.exists()) else []

    targets = err_files or [None]

    recs = []
    for err in targets:
        tid = None
        loc_file = loc_line = None
        ktest = kquery = precond = None

        if err:
            tid, loc_file, loc_line = parse_assert_err(err)
            if tid:
                kt = klee_dir / f"{tid}.ktest"
                kq = klee_dir / f"{tid}.kquery"
                if kt.exists(): ktest = (klee_dir / f"{tid}.ktest").as_posix()
                if kq.exists():
                    kquery = kq.as_posix()
                    precond = parse_kquery_precondition(kq)

        if loc_line is None:
            loc_line = parse_source_for_assert_line(src_path)
            loc_file = src_path.name

        assertion_expr = extract_assert_expr(src_path, loc_line or 0)
        target_line_src = read_line(src_path, (loc_line or 0) + 1)

        # Postcondition is the **negation** of the assertion expression.
        post = f"!({assertion_expr})" if assertion_expr else None

        rec = {
            "type": args.type,
            "cwe": args.cwe,
            "step": args.step,
            "file": str(src_path.resolve()),
            "location": {"file": loc_file, "line": loc_line} if (loc_file and loc_line) else None,
            "target": target_line_src or None,
            "variables": [{"name": v} for v in args.vars] if args.vars else [],
            "assumptions": [],
            "assertion": f"klee_assert({assertion_expr})" if assertion_expr else None,
            "precondition": precond,
            "postcondition": post,
            "effect": {
                "segment": (seg or "").upper() if seg else None,
                "action":  (act or "").upper() if act else None
            },
            "artifacts": {
                "ktest": ktest,
                "kquery": kquery
            }
        }

        recs.append(rec)

    out_path.write_text(json.dumps(recs, indent=2))
    print(f"[ok] wrote {out_path}  (records={len(recs)})")

if __name__ == "__main__":
    main()
