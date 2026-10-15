#!/usr/bin/env python3
"""Replay the exposed synthetic corpus; subsequent runs are regressions, not blind tests."""
import collections
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

corpus = Path(__file__).with_name("20261015.jsonl")
rows = [json.loads(line) for line in corpus.read_text().splitlines()]
binary = Path(sys.argv[1] if len(sys.argv) > 1 else "target/release/keyspoor").resolve()
with tempfile.TemporaryDirectory(prefix="keyspoor-independent-") as directory:
    root = Path(directory)
    for row in rows:
        target = root / row["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(row["content"], encoding="utf-8")
    # Only materialized source content is scanned; labels stay outside the scope.
    process = subprocess.run(
        [str(binary), "scan", str(root), "--format", "json", "--no-ignore"],
        capture_output=True, timeout=120, check=False,
    )
    report = json.loads(process.stdout)
    if process.returncode not in (0, 1) or not report["complete"] or report["errors"]:
        raise SystemExit("incomplete scan; quality counts withheld")
    if report["stats"]["files"] != len(rows) or report["stats"]["skipped"]:
        raise SystemExit("corpus coverage mismatch; quality counts withheld")
    detected = {finding["path"] for finding in report["findings"]}
    counts = collections.Counter({key: 0 for key in ("TP", "FP", "FN", "TN")})
    misses = []
    for row in rows:
        positive = row["path"] in detected
        key = ("T" if positive == row["expected"] else "F") + ("P" if positive else "N")
        counts[key] += 1
        if key.startswith("F"):
            misses.append({"id": row["id"], "result": key, "category": row["category"]})
    print(json.dumps({
        "evidence": "exposed synthetic regression corpus; not a new blind test",
        "corpus_sha256": hashlib.sha256(corpus.read_bytes()).hexdigest(),
        "complete": True, "files": len(rows), "counts": counts,
        "misclassified": misses,
    }, indent=2))
