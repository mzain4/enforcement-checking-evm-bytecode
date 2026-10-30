"""Attach a separately supplied plain-file evidence snapshot; never replace an unexplained mismatch."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from artifact_data import ROOT, ensure_data, verify_data
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', type=Path, help='Root of an existing raw evidence snapshot')
parser.add_argument('--verify', action='store_true')
args = parser.parse_args()
if args.source:
    source = args.source.resolve()
    entries = json.loads((ROOT / 'data/EVIDENCE_SHA256.json').read_text())['files']
    for index, (name, expected) in enumerate(entries.items(), 1):
        original, target = (source / name).resolve(), (ROOT / name).resolve()
        if not original.is_relative_to(source) or not target.is_relative_to(ROOT):
            raise ValueError('Evidence path leaves its supplied root')
        if target.is_file():
            if hashlib.sha256(target.read_bytes()).hexdigest() != expected:
                raise ValueError('Existing evidence differs; preserved: ' + name)
            continue
        if not original.is_file() or hashlib.sha256(original.read_bytes()).hexdigest() != expected:
            raise ValueError('Missing or mismatched source evidence: ' + name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, target)
        if index % 10000 == 0:
            print('Prepared', index, '/', len(entries), flush=True)
ensure_data()
if args.verify:
    report = verify_data()
    print(json.dumps(report, indent=2))
    raise SystemExit(not report['passed'])
print('Benchmark evidence is ready')
