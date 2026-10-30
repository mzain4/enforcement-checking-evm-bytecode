"""Validate corrected-run code/input identities and preserve the original-record comparison."""
from pathlib import Path
import json
import evaluation as e


def verify_correction():
    problems = []
    method = e.read(e.HERE / 'METHOD_SHA256.json')['files']
    for name, expected in method.items():
        if e.sha(e.HERE / name) != expected:
            problems.append('current method identity: ' + name)
    jobs = 0
    records = 0
    statuses = 0
    corrected = e.SOURCE / 'callcode-correction'
    for view, dataset, expected_inputs in [('released', 'dataset', 1431), ('withdrawal', 'withdrawal-view-v02', 62)]:
        for arm in ['presence', 'local', 'full', 'no-origin', 'no-guard', 'no-callresult',
                    'no-membership', 'full-repeat-2', 'full-repeat-3']:
            name = view + '-' + arm
            config = e.read(corrected / name / 'run.json')
            if (config['code_sha256'] != method or config['inputs'] != expected_inputs
                    or config['labels_read'] or config['outer_cap_seconds'] != 60 or config['workers'] != 8
                    or config['input_inventory_sha256'] != e.sha(e.SOURCE / dataset / 'inputs.jsonl')):
                problems.append('corrected run identity: ' + name)
            paths = sorted((corrected / name / 'runs').glob('*.json'))
            if len(paths) != expected_inputs:
                problems.append('corrected run population: ' + name)
            for path in paths:
                now = e.read(path)['result']
                old = e.read(e.SOURCE / name / 'runs' / path.name)['result']
                for swc in ['104', '105', '115']:
                    a = now.get('properties', {}).get(swc, {}).get('status', now.get('status', 'error'))
                    b = old.get('properties', {}).get(swc, {}).get('status', old.get('status', 'error'))
                    if a != b:
                        problems.append('original/corrected status: ' + name + '/' + path.name + '/' + swc)
                    statuses += 1
                records += 1
            jobs += 1
    result = {'passed': not problems, 'problems': problems, 'corrected_jobs': jobs,
              'records': records, 'property_status_comparisons': statuses,
              'scope': 'corrected candidate identities; original archives preserved; no reference changes'}
    print(json.dumps(result, indent=2))
    return result


if __name__ == '__main__':
    raise SystemExit(not verify_correction()['passed'])
