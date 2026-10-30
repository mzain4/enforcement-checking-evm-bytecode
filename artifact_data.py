"""Check the ordinary benchmark evidence files included in this repository."""
from pathlib import Path, PurePosixPath
import hashlib
import json

ROOT = Path(__file__).resolve().parent
CATALOG = ROOT / 'data/ASSETS.json'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def target(name):
    parts = PurePosixPath(name)
    if parts.is_absolute() or '..' in parts.parts or '\\' in name or ':' in name:
        raise ValueError('Invalid evidence path: ' + name)
    path = (ROOT / name).resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError('Evidence path leaves repository: ' + name)
    return path


def ensure_data():
    catalog = json.loads(CATALOG.read_text())
    if catalog.get('format') != 'plain-files':
        raise ValueError('Expected the plain-file evidence catalog')
    required = [ROOT / catalog['manifest'], ROOT / 'experiments/dataset/inputs.jsonl',
                ROOT / 'experiments/withdrawal-view-v02/inputs.jsonl']
    for path in required:
        if not path.is_file():
            raise FileNotFoundError('Benchmark evidence is missing: ' + str(path.relative_to(ROOT)) +
                                    '. Run python tools/prepare_data.py --source PATH_TO_RAW_EVIDENCE --verify')


def verify_data():
    ensure_data()
    catalog = json.loads(CATALOG.read_text())
    entries = json.loads((ROOT / catalog['manifest']).read_text())['files']
    problems = []
    if len(entries) != catalog['total_files']:
        problems.append('Evidence population differs from catalog')
    for name, digest in entries.items():
        path = target(name)
        if not path.is_file() or sha(path) != digest:
            problems.append('evidence: ' + name)
    return {'passed': not problems, 'files': len(entries), 'problems': problems}
