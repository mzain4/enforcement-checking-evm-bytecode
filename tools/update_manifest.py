"""Record byte identities of the repository payload tracked by Git."""
from pathlib import Path
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
files = {}
evidence = set(json.loads((ROOT / 'data/EVIDENCE_SHA256.json').read_text())['files'])
for index, name in enumerate(n for n in names if n and n != 'MANIFEST.json'):
    if name in evidence:
        continue  # Canonical evidence has its own tracked identity manifest.
    p = ROOT / name
    if not p.is_file():
        raise RuntimeError('Tracked payload missing: ' + name)
    files[name] = hashlib.sha256(p.read_bytes()).hexdigest()
    if index and index % 10000 == 0:
        print('Hashed', index, 'tracked files', flush=True)
(ROOT / 'MANIFEST.json').write_text(json.dumps({'files': files, 'method_identity': 'METHOD_SHA256.json'}, indent=2, sort_keys=True) + '\n')
print('Manifest records', len(files), 'tracked payload files')
