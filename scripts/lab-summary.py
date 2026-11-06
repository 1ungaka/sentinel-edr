#!/usr/bin/env python3
"""lab-summary.py — per-class detection rate from `cau eval` reports.

Usage: lab-summary.py <report.json> [<report.json> ...]

Prints aggregates only, which is the one thing allowed to be read from the
heldout split: see scripts/build-lab-corpus.py.
"""
import json
import sys


def summarize(path):
    with open(path) as f:
        r = json.load(f)
    t = r["totals"]
    mal, ben = t["tp"] + t["fn"], t["fp"] + t["tn"]
    print(f"{r['run']['corpus_name']}: detected {t['tp']}/{mal} "
          f"({100 * t['tp'] / max(mal, 1):.1f}%), false positives {t['fp']}/{ben} "
          f"({100 * t['fp'] / max(ben, 1):.2f}%), errors {len(r.get('errors') or [])}")
    for f in sorted(r["by_family"], key=lambda f: f["family"]):
        if f["recall"] is None:  # the benign family has no recall
            continue
        print(f"  {f['family']:24s} {f['detected']:5d}/{f['samples']:<5d} {100 * f['recall']:6.1f}%")
    print("  detector                    hits  exclusive   fp")
    for d in sorted(r["by_detector"], key=lambda d: -d["counts"]["tp"]):
        if d["counts"]["tp"] or d["counts"]["fp"]:
            print(f"  {d['detector']:24s} {d['counts']['tp']:7d} {d['exclusive_hits']:10d} {d['counts']['fp']:4d}")


if __name__ == "__main__":
    for p in sys.argv[1:]:
        summarize(p)
