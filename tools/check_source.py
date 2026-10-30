"""Check the source-release payload and detector identity without requiring benchmark data."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
problems = []
count = 0
for filename in ['MANIFEST.json', 'METHOD_SHA256.json']:
    for name, expected in json.loads((ROOT / filename).read_text())['files'].items():
        path = ROOT / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            problems.append(name)
        count += 1
print(json.dumps({'passed': not problems, 'problems': problems, 'identities_checked': count,
                  'scope': 'source release and method identities; no benchmark or score validation'}))
raise SystemExit(bool(problems))
