"""Download required compiler versions and check official release SHA-256 values."""
from pathlib import Path
import argparse
import hashlib
import json
import platform
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    sys.path.insert(0, str(ROOT))
    from artifact_data import ensure_data
    ensure_data()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--platform', choices=['windows-amd64', 'linux-amd64'],
                   default='windows-amd64' if platform.system() == 'Windows' else 'linux-amd64')
    args = p.parse_args()
    correspondence = json.loads((ROOT / 'experiments/source-correspondence/runtime-matches.json').read_text())
    items = [json.loads(s) for s in (ROOT / 'experiments/withdrawal-view-v02/inputs.jsonl').read_text().splitlines() if s.strip()]
    versions = {r['compiler_version'] for r in correspondence.values()} | {r['compiler_version'] for r in items if r.get('compiler_version')}
    versions |= {'0.8.4', '0.8.38'}
    base = 'https://binaries.soliditylang.org/' + args.platform + '/'
    with urllib.request.urlopen(base + 'list.json', timeout=60) as response:
        listing = json.load(response)
    output = ROOT / 'tools/solc'
    output.mkdir(exist_ok=True)
    for version in sorted(versions):
        leaf = listing['releases'][version]
        build = next(r for r in listing['builds'] if r['path'] == leaf)
        expected = build['sha256'].removeprefix('0x')
        target = output / ('solc-' + version + ('.exe' if args.platform.startswith('windows') else ''))
        if target.exists():
            if hashlib.sha256(target.read_bytes()).hexdigest() != expected:
                raise RuntimeError('Existing compiler differs; preserve and inspect: ' + str(target))
        else:
            with urllib.request.urlopen(base + leaf, timeout=120) as response:
                data = response.read()
            if hashlib.sha256(data).hexdigest() != expected:
                raise RuntimeError('Downloaded compiler hash differs: ' + version)
            target.write_bytes(data)
            target.chmod(target.stat().st_mode | 0o111)
        print(version, expected, target, flush=True)
    (output / 'release-list.json').write_text(json.dumps(listing, indent=2))


if __name__ == '__main__':
    main()
