"""Actual source-tool execution with checked executable correspondence and explicit target scope."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
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
MAPPING = {'unchecked-lowlevel': '104', 'unchecked-send': '104', 'arbitrary-send-eth': '105', 'tx-origin': '115'}


def compiler_path(version):
    directory = Path(os.environ.get('SOLC_DIR', ROOT / 'tools/solc'))
    names = [f'solc-{version}', f'solc-{version}.exe', f'solc-v{version}', f'solc-{version}/solc.exe']
    for name in names:
        p = directory / name
        if p.is_file():
            return str(p.resolve())
    raise FileNotFoundError(f'Solidity {version} required under {directory}; set SOLC_DIR')


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf8')


def rows(path):
    return [json.loads(line) for line in path.read_text(encoding='utf8').splitlines() if line.strip()]


def worker(args):
    import inspect
    import importlib.metadata
    from slither.slither import Slither
    import slither.detectors.all_detectors as detectors
    from source_identity import executable
    request = json.loads(Path(args.request).read_text())
    options = []
    if request.get('evm_version'):
        options += ['--evm-version', request['evm_version']]
    if request.get('optimized'):
        options += ['--optimize', '--optimize-runs', str(request.get('optimizer_runs', 200))]
    analysis = Slither(request['source_path'], solc=request['compiler_path'],
                       solc_args=' '.join(options), compile_force_framework='solc')
    classes = [c for _, c in inspect.getmembers(detectors, inspect.isclass)
               if getattr(c, 'ARGUMENT', None) in MAPPING]
    for c in classes:
        analysis.register_detector(c)
    targets = analysis.get_contract_from_name(request['target'])
    if len(targets) != 1:
        raise ValueError('Target contract identity ambiguous')
    target_names = {request['target']} | {c.name for c in targets[0].inheritance}
    compiled = []
    for compilation in analysis.crytic_compile.compilation_units.values():
        for source in compilation.source_units.values():
            if request['target'] in source.bytecodes_runtime:
                compiled.append(source.bytecodes_runtime[request['target']])
    reference = Path(request['runtime_path']).read_text().strip()
    matches = [r for r in compiled if r and executable(r) == executable(reference)]
    if not matches:
        raise ValueError('Source/compiler executable does not match scored runtime')
    raw = [r for group in analysis.run_detectors() for r in group]
    def belongs(result):
        for element in result.get('elements', []):
            if element.get('type') == 'contract' and element.get('name') in target_names:
                return True
            if element.get('type_specific_fields', {}).get('parent', {}).get('name') in target_names:
                return True
        return False
    scoped = [r for r in raw if belongs(r)]
    result = {'status': 'ok', 'slither_version': importlib.metadata.version('slither-analyzer'),
              'detector_mapping': MAPPING, 'target_scope': sorted(target_names),
              'executable_correspondence': True, 'properties': {}, 'raw_detections': raw, 'target_detections': scoped}
    for swc in ['104', '105', '115']:
        findings = [r for r in scoped if MAPPING.get(r['check']) == swc]
        result['properties'][swc] = {'status': 'positive' if findings else 'negative',
                                     'reason': 'actual configured Slither detector output', 'evidence': findings}
    print(json.dumps(result, sort_keys=True))


def run(args):
    out = ROOT / 'runs' / args.output
    inventory_root = HERE / ('withdrawal-view-v02' if args.view == 'withdrawal-v02' else 'withdrawal-view') if args.view.startswith('withdrawal') else DATA
    inventory = rows(inventory_root / 'inputs.jsonl')
    if args.profile == 'common':
        if args.view != 'released':
            raise ValueError('Use --profile all for the withdrawal view')
        wanted = set(json.loads((HERE / 'common-cohort.json').read_text())['runtime_sha256'])
        inventory = [r for r in inventory if r['runtime_sha256'] in wanted]
    if args.view == 'released':
        correspondence = json.loads((HERE / 'source-correspondence/runtime-matches.json').read_text())
    else:
        correspondence = {}
    out.mkdir(parents=True, exist_ok=True)
    if (out / 'configuration.json').exists() and not args.resume:
        raise ValueError('Preserve prior Slither run')
    config = {'method': 'slither', 'version': '0.11.6', 'view': args.view, 'profile': args.profile, 'mapping': MAPPING,
              'process_cap_seconds': 60, 'workers': args.workers,
              'input_inventory_sha256': hashlib.sha256((inventory_root / 'inputs.jsonl').read_bytes()).hexdigest(),
              'labels_read': False}
    if (out / 'configuration.json').exists() and json.loads((out / 'configuration.json').read_text()) != config:
        raise ValueError('Resume configuration differs')
    save(out / 'configuration.json', config)
    def execute(item):
        identity = item['runtime_sha256']
        target = out / 'runs' / (identity + '.json')
        if args.resume and target.exists():
            return json.loads(target.read_text())
        start = time.monotonic()
        if args.view.startswith('withdrawal'):
            match = item if item['runtime_path'] else None
            request = {'source_path': str((inventory_root / 'sources' / Path(item['source_path'].replace('\\', '/')).name).resolve()), 'target': item['target'],
                       'compiler_path': compiler_path(item['compiler_version']),
                       'runtime_path': str((inventory_root / item['runtime_path']).resolve()) if item['runtime_path'] else None,
                       'optimized': False, 'evm_version': None}
        else:
            match = correspondence.get(identity)
            request = {'source_path': str((DATA / match['source_path']).resolve()), 'target': match['contract_name'],
                       'compiler_path': compiler_path(match['compiler_version']), 'runtime_path': str((DATA / item['runtime_path']).resolve()),
                       'optimized': match['optimized'], 'evm_version': match['evm_version'], 'optimizer_runs': 200} if match else None
        if not match:
            result = {'status': 'unsupported', 'reason': 'no verified source/compiler/runtime correspondence', 'properties': {}}
        else:
            request_path = out / 'requests' / (identity + '.json')
            save(request_path, request)
            command = [os.environ.get('SLITHER_PYTHON', sys.executable), '-X', 'utf8', '-B', str(Path(__file__).resolve()),
                       'worker', '--request', str(request_path.resolve())]
            try:
                proc = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding='utf8',
                                      errors='replace', timeout=60, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
                (out / (identity + '.stdout')).write_text(proc.stdout, encoding='utf8')
                (out / (identity + '.stderr')).write_text(proc.stderr, encoding='utf8')
                result = json.loads(proc.stdout) if proc.returncode == 0 else {
                    'status': 'error', 'reason': proc.stderr[-1500:], 'properties': {}}
            except subprocess.TimeoutExpired:
                result = {'status': 'timeout', 'reason': '60-second outer cap', 'properties': {}}
        record = {'input_id': item['input_id'], 'runtime_sha256': identity, 'result': result,
                  'process_seconds': time.monotonic() - start}
        save(target, record)
        print(args.output, identity[:12], result['status'], flush=True)
        return record
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        records = list(pool.map(execute, inventory))
    save(out / 'run.json', dict(config, inputs=len(records), elapsed_seconds=time.monotonic() - started))


def score(args):
    out = ROOT / 'runs' / args.output
    config = json.loads((out / 'configuration.json').read_text())
    source = HERE / ('withdrawal-view-v02' if config['view'] == 'withdrawal-v02' else 'withdrawal-view') if config['view'].startswith('withdrawal') else DATA
    labels = rows(source / 'labels.jsonl')
    predictions = []
    for label in labels:
        result = json.loads((out / 'runs' / (label['runtime_sha256'] + '.json')).read_text())['result']
        prop = result.get('properties', {}).get(label['swc'], {})
        predictions.append({'case_id': label['case_id'], 'status': prop.get('status', result['status']),
                            'reason': prop.get('reason', result.get('reason')), 'property': label['swc'],
                            'evidence': prop.get('evidence', [])})
    spec = importlib.util.spec_from_file_location('frozen_cgt_score', OLD / 'frozen_scorer.py')
    scorer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scorer)
    metrics = scorer.score_records(labels, predictions, args.output)
    (out / 'predictions.jsonl').write_text(''.join(json.dumps(r, sort_keys=True) + '\n' for r in predictions), encoding='utf8')
    save(out / 'metrics.json', metrics)
    print(json.dumps({'macro_f1': metrics['macro_f1'], 'counts': metrics['primary_end_to_end']['counts']}, indent=2))


def main():
    from artifact_data import ensure_data
    ensure_data()
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('worker')
    p.add_argument('--request', required=True)
    p = sub.add_parser('run')
    p.add_argument('--view', choices=['released', 'withdrawal', 'withdrawal-v02'], required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--workers', type=int, default=4)
    p.add_argument('--profile', choices=['common', 'all'], default='common')
    p.add_argument('--resume', action='store_true')
    p = sub.add_parser('score')
    p.add_argument('--output', required=True)
    args = parser.parse_args()
    {'worker': worker, 'run': run, 'score': score}[args.command](args)


if __name__ == '__main__':
    main()
