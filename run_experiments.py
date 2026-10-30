"""Execute label-free internal arms with input/code identities and a 60-second outer cap."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time

W = Path(__file__).resolve().parent
ROOT = W
EXP = W / 'experiments'
ARMS = ['presence', 'local', 'full', 'no-origin', 'no-guard', 'no-callresult', 'no-membership']


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf8')


def rows(path):
    return [json.loads(line) for line in path.read_text(encoding='utf8').splitlines() if line.strip()]


def data_root(view):
    return EXP / ('dataset' if view == 'released' else 'withdrawal-view-v02')


def facts_for(item, view):
    if view == 'released':
        possible = [EXP / 'dataset/facts' / item['runtime_sha256'],
                    EXP / 'pilot/facts' / item['runtime_sha256']]
    else:
        possible = [EXP / 'withdrawal-view-v02/facts' / item['runtime_sha256']]
    return next((p for p in possible if (p / 'contract.tac').exists()), possible[0])


def worker(args):
    sys.path.insert(0, str(Path(args.code).resolve()))
    def reference_guard(event, arguments):
        if event == 'open' and isinstance(arguments[0], (str, bytes, os.PathLike)):
            if Path(os.fsdecode(arguments[0])).name in {'labels.jsonl', 'predictions.jsonl'}:
                raise PermissionError('Reference/prediction reads are forbidden during detection')
    sys.addaudithook(reference_guard)
    from implementation.enforcement_state.analyze import analyse_facts
    flags = {name: args.arm != 'presence' for name in
             ['callresult_dependency', 'origin_role', 'guard_dominance']}
    if args.arm == 'no-origin':
        flags['origin_role'] = False
    elif args.arm == 'no-guard':
        flags['guard_dominance'] = False
    elif args.arm == 'no-callresult':
        flags['callresult_dependency'] = False
    credential = args.arm not in {'presence', 'local'}
    result = analyse_facts(Path(args.facts), credential_integrity=credential, base_flags=flags,
                           membership_credential=args.arm != 'no-membership')
    print(json.dumps(result, sort_keys=True))


def run(args):
    data = data_root(args.view)
    inventory = rows(data / 'inputs.jsonl')
    if args.profile == 'common':
        if args.view != 'released':
            raise ValueError('The common profile is defined on released runtimes')
        wanted = set(json.loads((EXP / 'common-cohort.json').read_text())['runtime_sha256'])
        inventory = [r for r in inventory if r['runtime_sha256'] in wanted]
    out = (W / 'runs' / args.output).resolve()
    if not out.is_relative_to((W / 'runs').resolve()):
        raise ValueError('Output must stay under runs/')
    if out.exists() and not args.resume:
        raise ValueError('Choose a new output name or explicitly resume its matching configuration')
    out.mkdir(parents=True, exist_ok=True)
    code_root = W.resolve()
    config = {'method': args.arm, 'view': args.view, 'profile': args.profile, 'workers': args.workers,
              'outer_cap_seconds': 60, 'code_root': '.',
              'input_inventory_sha256': hashlib.sha256((data / 'inputs.jsonl').read_bytes()).hexdigest(),
              'code_sha256': {p.relative_to(code_root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in sorted((code_root / 'implementation').rglob('*.py'))}, 'labels_read': False}
    path = out / 'configuration.json'
    if path.exists():
        if not args.resume or json.loads(path.read_text()) != config:
            raise ValueError('Preserve existing run/configuration')
    else:
        save(path, config)

    def execute(item):
        identity = item['runtime_sha256']
        target = out / 'runs' / (identity + '.json')
        if args.resume and target.exists():
            return json.loads(target.read_text())
        facts = facts_for(item, args.view)
        start = time.monotonic()
        if not (facts / 'contract.tac').exists():
            result = {'status': 'unsupported', 'properties': {}, 'reason': 'preprocessing unavailable'}
        else:
            actual = hashlib.sha256(bytes.fromhex(
                ''.join((facts / 'bytecode.hex').read_text().split()).removeprefix('0x'))).hexdigest()
            if actual != identity:
                raise ValueError('Facts/input identity differs: ' + identity)
            command = [sys.executable, '-X', 'utf8', '-B', str(Path(__file__).resolve()), 'worker',
                       '--facts', str(facts), '--arm', args.arm, '--code', str(code_root)]
            try:
                proc = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding='utf8',
                                      errors='replace', timeout=60,
                                      env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
                (out / (identity + '.stdout')).write_text(proc.stdout, encoding='utf8')
                (out / (identity + '.stderr')).write_text(proc.stderr, encoding='utf8')
                result = json.loads(proc.stdout) if proc.returncode == 0 else {
                    'status': 'error', 'reason': proc.stderr[-1500:], 'properties': {}}
            except subprocess.TimeoutExpired:
                result = {'status': 'timeout', 'reason': '60-second outer cap', 'properties': {}}
        record = {'runtime_sha256': identity, 'input_id': item['input_id'], 'facts_path': str(facts),
                  'result': result, 'process_seconds': time.monotonic() - start}
        save(target, record)
        return record

    started = time.monotonic()
    records = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for index, record in enumerate(pool.map(execute, inventory), 1):
            records.append(record)
            if index % 200 == 0:
                print(args.output, index, '/', len(inventory), flush=True)
    save(out / 'run.json', dict(config, inputs=len(records), elapsed_seconds=time.monotonic() - started))
    print(args.output, 'done', len(records), flush=True)


def main():
    from artifact_data import ensure_data
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('worker')
    p.add_argument('--facts', required=True)
    p.add_argument('--arm', choices=ARMS, required=True)
    p.add_argument('--code', required=True)
    p = sub.add_parser('run')
    p.add_argument('--view', choices=['released', 'withdrawal'], required=True)
    p.add_argument('--arm', choices=ARMS, required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--profile', choices=['all', 'common'], default='all')
    p.add_argument('--workers', type=int, default=4)
    p.add_argument('--resume', action='store_true')
    args = parser.parse_args()
    if args.command == 'run':
        ensure_data()
    {'worker': worker, 'run': run}[args.command](args)


if __name__ == '__main__':
    main()
