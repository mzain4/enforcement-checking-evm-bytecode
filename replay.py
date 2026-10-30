"""Verify a fresh frozen-checker replay; no labels enter worker analysis.

Default: full method on the 267-runtime common cohort. --profile controls replays
authored bit-field and metamorphic controls. Native external tools are not rerun.
"""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import argparse
import importlib.util
import json
import subprocess
import sys
import tempfile
import time
import evaluation as e


def worker(facts):
    sys.path.insert(0, str(e.HERE))
    from implementation.enforcement_state.analyze import analyse_facts
    if not (facts / 'contract.tac').exists():
        result = {'status': 'unsupported', 'properties': {}, 'reason': 'preprocessing unavailable'}
    else:
        result = analyse_facts(facts, credential_integrity=True,
                               base_flags={'callresult_dependency': True, 'origin_role': True, 'guard_dominance': True})
    print(json.dumps(result, sort_keys=True))


def controls():
    sys.path.insert(0, str(e.HERE))
    from implementation.enforcement_state.analyze import analyse_facts
    spec = importlib.util.spec_from_file_location('authored_controls', e.HERE / 'support/controls.py')
    if spec is None or spec.loader is None:
        raise ImportError('Authored controls cannot be loaded')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    outcomes = []
    with tempfile.TemporaryDirectory() as temp:
        for name, (expected, _) in module.CASES.items():
            actual = analyse_facts(module.build(Path(temp) / name, name))['properties']['105']['status']
            if actual != expected:
                raise ValueError((name, expected, actual))
            outcomes.append(actual)
        for name in ['caller_setter','guarded_setter','packed_neighbor','shifted_setter','multiply_setter','initialization_gate']:
            for split, rename in [(True, False), (True, True)]:
                facts = module.build(Path(temp)/(name+str(rename)), name, split_write=split, rename=rename)
                actual = analyse_facts(facts)['properties']['105']['status']
                if actual != module.CASES[name][0]:
                    raise ValueError((name, split, rename))
                outcomes.append(actual)
    result = {'passed': True, 'unique_authored_programs_replayed': len(outcomes),
              'fact_controls': len(module.CASES), 'metamorphic_families': 6,
              'scope': 'authored development controls; not independently labelled benchmark cases'}
    print(json.dumps(result, indent=2))
    return result


def replay(profile, workers):
    if profile == 'controls':
        return controls()
    inventory = e.rows(e.SOURCE / 'dataset/inputs.jsonl')
    if profile == 'common':
        ids = set(e.read(e.SOURCE / 'common-cohort.json')['runtime_sha256'])
        inventory = [r for r in inventory if r['runtime_sha256'] in ids]
    started = time.monotonic()
    def check(item):
        facts = e.SOURCE / 'dataset/facts' / item['runtime_sha256']
        command = [sys.executable, '-X', 'utf8', '-B', str(Path(__file__).resolve()),
                   '--worker', str(facts)]
        try:
            proc = subprocess.run(command, capture_output=True, text=True, encoding='utf8', timeout=60)
            actual = json.loads(proc.stdout) if proc.returncode == 0 else {'status': 'error', 'properties': {}}
        except subprocess.TimeoutExpired:
            actual = {'status': 'timeout', 'properties': {}}
        expected = e.raw_record('released-full', item['runtime_sha256'])['result']
        mismatches = []
        for swc in ['104','105','115']:
            a = actual.get('properties', {}).get(swc, {}).get('status', actual.get('status', 'error'))
            b = expected.get('properties', {}).get(swc, {}).get('status', expected.get('status', 'error'))
            if a != b:
                mismatches.append({'runtime_sha256': item['runtime_sha256'], 'property': swc, 'expected': b, 'actual': a})
        return mismatches
    with ThreadPoolExecutor(max_workers=workers) as pool:
        differences = [r for group in pool.map(check, inventory) for r in group]
    result = {'profile': profile, 'inputs_replayed': len(inventory), 'properties_per_input': 3,
              'differences': differences, 'passed': not differences,
              'process_cap_seconds': 60, 'elapsed_seconds': time.monotonic()-started,
              'scope': 'new execution of full checker; excludes external detectors and frontend'}
    print(json.dumps(result, indent=2))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker')
    parser.add_argument('--profile', choices=['common','census','controls'], default='common')
    parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args()
    if args.worker:
        worker(Path(args.worker))
    else:
        raise SystemExit(0 if replay(args.profile, args.workers)['passed'] else 1)
