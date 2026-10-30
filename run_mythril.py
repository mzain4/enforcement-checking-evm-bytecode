"""Run actual external analyzers on input identities; join references only during scoring."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import shutil
import time

ROOT = Path(__file__).resolve().parent
HERE = ROOT / 'experiments'
DATA = HERE / 'dataset'
OLD = ROOT / 'support'


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf8')


def read_rows(path):
    return [json.loads(r) for r in path.read_text(encoding='utf8').splitlines() if r.strip()]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def mythril(item, code_path, out, transactions):
    command = [str(Path(shutil.which(os.environ.get('MYTHRIL_EXE', 'myth')) or os.environ.get('MYTHRIL_EXE', 'myth'))), 'analyze', '--codefile', str(code_path),
               '--bin-runtime', '-o', 'json', '--no-onchain-data', '-m', 'EtherThief,UncheckedRetval,TxOrigin',
               '--execution-timeout', '60', '--solver-timeout', '5000', '--max-depth', '64',
               '--transaction-count', str(transactions)]
    start = time.monotonic()
    record = {'command': command, 'runtime_sha256': item['runtime_sha256'], 'properties': {}}
    try:
        proc = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding='utf-8-sig',
                              errors='replace', timeout=90, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        elapsed = time.monotonic() - start
        (out / (item['runtime_sha256'] + '.stdout')).write_text(proc.stdout, encoding='utf8')
        (out / (item['runtime_sha256'] + '.stderr')).write_text(proc.stderr, encoding='utf8')
        record['returncode'] = proc.returncode
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            record.update(status='error', reason='Mythril stdout was not JSON')
        else:
            record['raw_output'] = payload
            if not payload.get('success'):
                record.update(status='error', reason=str(payload.get('error')))
            else:
                record['status'] = 'ok'
                # Preserve the existing conservative heuristic and identify it explicitly. It is
                # not a proof of search exhaustion; positive findings remain positive under a cap.
                truncated = elapsed >= 57
                for swc in ['104', '105', '115']:
                    matches = [r for r in payload.get('issues', []) if str(r.get('swc-id')) == swc]
                    if matches:
                        prop = {'status': 'positive', 'evidence': matches, 'reason': 'actual Mythril issue'}
                    elif truncated:
                        prop = {'status': 'unknown', 'reason': 'no issue; elapsed time near execution cap (heuristic)'}
                    else:
                        prop = {'status': 'negative', 'reason': 'no issue before configured analysis ended'}
                    record['properties'][swc] = prop
                record['truncation_heuristic'] = truncated
    except subprocess.TimeoutExpired as error:
        record.update(status='timeout', reason='90-second outer process cap')
        for key in ['stdout', 'stderr']:
            data = getattr(error, key, None)
            if data:
                if isinstance(data, bytes):
                    data = data.decode('utf8', errors='replace')
                (out / (item['runtime_sha256'] + '.' + key)).write_text(data, encoding='utf8')
    record['process_seconds'] = time.monotonic() - start
    return record


def run(args):
    population = HERE / 'withdrawal-view-v02' if args.population == 'withdrawal-v02' else HERE / 'pilot' if args.population == 'pilot' else DATA
    inputs = read_rows(population / 'inputs.jsonl')
    if args.profile == 'common':
        cohort = json.loads((HERE / 'common-cohort.json').read_text())
        wanted = set(cohort['runtime_sha256'])
        inputs = [r for r in inputs if r['runtime_sha256'] in wanted]
    out = ROOT / 'runs' / args.output
    out.mkdir(parents=True, exist_ok=True)
    if args.resume and not (out / 'configuration.json').exists():
        raise ValueError('Resume requires an existing configuration identity')
    config = {'method': 'mythril', 'version': '0.24.8', 'population': args.population,
              'profile': args.profile,
              'input_inventory_sha256': sha(population / 'inputs.jsonl'),
              'cli_sha256': sha(Path(shutil.which(os.environ.get('MYTHRIL_EXE', 'myth')) or os.environ.get('MYTHRIL_EXE', 'myth'))), 'transactions': args.transactions,
              'execution_seconds': 60, 'solver_ms': 5000, 'depth': 64, 'outer_cap_seconds': 90,
              'workers': args.workers, 'label_access': False}
    if (out / 'configuration.json').exists():
        if json.loads((out / 'configuration.json').read_text()) != config:
            raise ValueError('Configuration differs from preserved run')
        if not args.resume:
            raise ValueError('Preserve previous run; choose a new output')
    else:
        save(out / 'configuration.json', config)
    def process(item):
        target = out / 'runs' / (item['runtime_sha256'] + '.json')
        if args.resume and target.exists():
            return json.loads(target.read_text())
        if args.reuse_pilot:
            previous = HERE / args.reuse_pilot
            source = previous / 'runs' / (item['runtime_sha256'] + '.json')
            if source.is_file():
                old_config = json.loads((previous / 'configuration.json').read_text())
                identity_keys = ['method', 'version', 'cli_sha256', 'transactions', 'execution_seconds',
                                 'solver_ms', 'depth', 'outer_cap_seconds']
                if any(old_config[k] != config[k] for k in identity_keys):
                    raise ValueError('Reused comparator configuration differs')
                record = json.loads(source.read_text())
                if record['runtime_sha256'] != item['runtime_sha256']:
                    raise ValueError('Reused comparator input differs')
                record['reused_from'] = str(source.relative_to(ROOT))
                record['reused_record_sha256'] = sha(source)
                save(target, record)
                for suffix in ['stdout', 'stderr']:
                    p = previous / (item['runtime_sha256'] + '.' + suffix)
                    if p.exists():
                        (out / p.name).write_bytes(p.read_bytes())
                return record
        if item.get('runtime_path'):
            # Pilot inventory paths are relative to HERE; full inventory paths are relative to DATA.
            code = (HERE if args.population == 'pilot' else population) / item['runtime_path']
        else:
            code = None
        if code is None or not code.exists():
            record = {'status': 'unsupported', 'reason': 'runtime unavailable', 'properties': {},
                      'runtime_sha256': item['runtime_sha256'], 'process_seconds': 0}
        else:
            actual = hashlib.sha256(bytes.fromhex(code.read_text().strip().removeprefix('0x'))).hexdigest()
            if actual != item['runtime_sha256']:
                raise ValueError('Runtime identity differs')
            record = mythril(item, code.resolve(), out, args.transactions)
        record['input_id'] = item['input_id']
        save(target, record)
        print(args.output, item['runtime_sha256'][:12], record['status'], flush=True)
        return record
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        records = list(pool.map(process, inputs))
    save(out / 'run.json', dict(config, completed_runtime_records=len(records),
                               elapsed_seconds=time.monotonic() - started,
                               record_sha256={r['runtime_sha256']: sha(out / 'runs' / (r['runtime_sha256'] + '.json')) for r in records}))


def score(args):
    out = ROOT / 'runs' / args.output
    config = json.loads((out / 'configuration.json').read_text())
    population = HERE / 'withdrawal-view-v02' if config['population'] == 'withdrawal-v02' else HERE / 'pilot' if config['population'] == 'pilot' else DATA
    labels = read_rows(population / 'labels.jsonl')
    if config.get('profile') == 'common':
        cohort = json.loads((HERE / 'common-cohort.json').read_text())
        wanted = set(cohort['runtime_sha256'])
        labels = [r for r in labels if r['runtime_sha256'] in wanted]
    predictions = []
    for label in labels:
        record = json.loads((out / 'runs' / (label['runtime_sha256'] + '.json')).read_text())
        prop = record.get('properties', {}).get(label['swc'], {})
        predictions.append({'case_id': label['case_id'], 'status': prop.get('status', record['status']),
                            'property': label['swc'], 'reason': prop.get('reason', record.get('reason')),
                            'evidence': prop.get('evidence', [])})
    spec = importlib.util.spec_from_file_location('frozen_cgt_score', OLD / 'frozen_scorer.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    metrics = module.score_records(labels, predictions, args.output)
    (out / 'predictions.jsonl').write_text(''.join(json.dumps(r, sort_keys=True) + '\n' for r in predictions), encoding='utf8')
    save(out / 'metrics.json', metrics)
    print(json.dumps({'output': args.output, 'macro_f1': metrics['macro_f1'],
                      'counts': metrics['primary_end_to_end']['counts']}, indent=2))


def main():
    from artifact_data import ensure_data
    ensure_data()
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('run')
    p.add_argument('--population', choices=['full', 'withdrawal-v02'], default='full')
    p.add_argument('--output', required=True)
    p.add_argument('--transactions', type=int, default=2)
    p.add_argument('--workers', type=int, default=4)
    p.add_argument('--resume', action='store_true')
    p.add_argument('--reuse-pilot')
    p.add_argument('--profile', choices=['all', 'common'], default='all')
    p = sub.add_parser('score')
    p.add_argument('--output', required=True)
    args = parser.parse_args()
    {'run': run, 'score': score}[args.command](args)


if __name__ == '__main__':
    main()
