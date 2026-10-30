"""Decode native outputs and regenerate fixed-reference evaluations.

No detector runs, reference changes or label access inside native-output decoding.
"""
from pathlib import Path
from collections import Counter
from functools import lru_cache
from artifact_data import ensure_data
import hashlib
import importlib.util
import json
import tarfile


HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'experiments'
MAPPING = {'UnhandledExceptionPattern': '104', 'UnrestrictedEtherFlowPattern': '105', 'TxOriginPattern': '115'}
INTERNAL = ['all-positive', 'all-negative', 'released-presence', 'released-local',
            'released-no-origin', 'released-no-guard', 'released-no-callresult', 'released-no-membership', 'released-full']
COMMON = ['all-positive', 'all-negative', 'released-presence', 'released-local',
          'released-no-origin', 'released-no-guard', 'released-no-callresult',
          'common-mythril-two-tx', 'full-slither', 'released-no-membership', 'released-full']
WITHDRAWAL = ['all-positive', 'all-negative', 'withdrawal-presence', 'withdrawal-local', 'withdrawal-no-origin', 'withdrawal-no-guard',
              'withdrawal-no-callresult', 'withdrawal-no-membership', 'withdrawal-v02-mythril', 'withdrawal-v02-slither', 'withdrawal-full']


def read(path):
    return json.loads(path.read_text(encoding='utf8'))


def rows(path):
    return [json.loads(line) for line in path.read_text(encoding='utf8').splitlines() if line.strip()]


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf8', newline='\n')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def classify_pattern(pattern, scope):
    """Collapse native matches, with positive/unknown precedence and target scoping."""
    types = set()
    ambiguous = False
    scoped = []
    ignored = 0
    for match in pattern.get('matches', []):
        kind = match.get('type')
        if kind not in {'VIOLATION', 'WARNING', 'CONFLICT', 'COMPLIANT'}:
            raise ValueError('Unexpected native verdict: ' + str(kind))
        locations = match.get('locations', [])
        if not locations:
            ambiguous |= kind != 'COMPLIANT'
            continue
        if not any(location.get('contract') in scope for location in locations):
            ignored += 1
            continue
        types.add(kind)
        scoped.append(match)
    status = 'positive' if 'VIOLATION' in types else 'unknown' if ambiguous or types & {'WARNING', 'CONFLICT'} else 'negative'
    return {'status': status, 'reason': 'scoped native match aggregation', 'matches': scoped,
            'ambiguous_location': ambiguous, 'out_of_scope_matches': ignored}


def decode_native(request, run, result):
    """Final run status is authoritative; a stale result cannot rescue a failed run."""
    if run['status'] != 'ok':
        return {'status': run['status'], 'properties': {}, 'stale_result_present': result is not None,
                'reason': 'final native request did not complete successfully'}
    if result is None or result.get('status') != 'actual_analysis_completed':
        raise ValueError('Successful run without actual native analysis')
    for key in ['source_sha256', 'compiler_version', 'target_scope']:
        if request[key] != result[key]:
            raise ValueError('Native request/result identity differs: ' + key)
    if hashlib.sha256(request['source'].encode()).hexdigest() != request['source_sha256']:
        raise ValueError('Source bytes differ')
    patterns = {p['pattern']: p for p in result['patterns']}
    if len(patterns) != len(result['patterns']) or set(patterns) != set(MAPPING):
        raise ValueError('Native configured pattern population differs')
    properties = {swc: classify_pattern(patterns[name], set(request['target_scope'])) for name, swc in MAPPING.items()}
    return {'status': 'ok', 'properties': properties, 'stale_result_present': False,
            'source_sha256': result['source_sha256'], 'target_scope': result['target_scope'],
            'compiler_version': result['compiler_version']}


def archive_bytes(tar, member):
    stream = tar.extractfile(member)
    if stream is None:
        raise ValueError("Archive member is not a regular file")
    with stream:
        return stream.read()


def export_securify():
    """Decode all 54 predeclared native requests before reading any labels."""
    protocol = read(SOURCE / 'securify-preparation/protocol.json')
    archive = SOURCE / 'credential-securify-batch-20261029.tar.gz'
    records = []
    counts = Counter()
    verdicts = Counter()
    stale = []
    with tarfile.open(archive) as tar:
        members = {m.name: m for m in tar.getmembers() if m.isfile()}
        roots = [name[:-len('protocol.json')] for name in members if name.endswith('/protocol.json')]
        if len(roots) != 1:
            raise ValueError('Native archive root ambiguous')
        root = roots[0]
        for item in protocol['requests']:
            name = root + item['request_path']
            raw = archive_bytes(tar, members[name])
            if hashlib.sha256(raw).hexdigest() != item['request_sha256']:
                raise ValueError('Native request bytes differ from frozen protocol')
            request = json.loads(raw)
            base = name[:-len('request.json')]
            run = json.loads(archive_bytes(tar, members[base + 'run.json']))
            if any(run[k] != item[k] for k in ['view', 'runtime_sha256', 'request_sha256']):
                raise ValueError('Native run/protocol differs')
            result = json.loads(archive_bytes(tar, members[base + 'result.json'])) if base + 'result.json' in members else None
            result_record = decode_native(request, run, result)
            counts[run['status']] += 1
            if result_record['stale_result_present']:
                stale.append(base + 'result.json')
            if run['status'] == 'ok':
                assert result is not None
                for p in result['patterns']:
                    verdicts.update(m['type'] for m in p['matches'])
            record = {'view': item['view'], 'runtime_sha256': item['runtime_sha256'],
                      'request_sha256': item['request_sha256'], 'result': result_record,
                      'raw_member': base + 'result.json', 'run': run}
            records.append(record)
            save(HERE / 'results/securify' / item['view'] / (item['runtime_sha256'] + '.json'), record)
    summary = {'requests': len(records), 'final_statuses': dict(counts), 'native_matches_in_successful_runs': dict(verdicts),
               'successful_requests_with_scoped_violation': sum(any(p['status'] == 'positive' for p in r['result']['properties'].values()) for r in records),
               'stale_result_files_ignored': stale, 'archive_sha256': sha(archive),
               'request_protocol_sha256': sha(SOURCE / 'securify-preparation/protocol.json'),
               'unit': 'native match records are not independent vulnerabilities or true positives'}
    save(HERE / 'securify/export-audit.json', summary)
    return records, summary


@lru_cache(maxsize=None)
def raw_record(method, identity):
    arms = {'presence', 'local', 'full', 'no-origin', 'no-guard', 'no-callresult',
            'no-membership', 'full-repeat-2', 'full-repeat-3'}
    internal = any(method == view + '-' + arm for view in ['released', 'withdrawal'] for arm in arms)
    base = SOURCE / 'callcode-correction' if internal else SOURCE
    return read(base / method / 'runs' / (identity + '.json'))


def predictions(labels, method, native, view):
    output = []
    for label in labels:
        if method.startswith('all-'):
            prop = {'status': method.removeprefix('all-'), 'reason': 'constant prediction control'}
        else:
            record = native[(view, label['runtime_sha256'])] if method == 'securify2' else raw_record(method, label['runtime_sha256'])
            result = record.get('result', record)
            prop = result.get('properties', {}).get(label['swc'], {})
            prop = {'status': prop.get('status', result.get('status', 'error')),
                    'reason': prop.get('reason', result.get('reason')), 'evidence': prop.get('evidence', prop.get('matches', []))}
        output.append({'case_id': label['case_id'], 'property': label['swc'], **prop})
    return output


def score_function():
    spec = importlib.util.spec_from_file_location('unchanged_cgt_scorer', HERE / 'support/frozen_scorer.py')
    if spec is None or spec.loader is None:
        raise ImportError('Frozen scorer cannot be loaded')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.score_records


def conservative(metric):
    count = metric['primary_end_to_end']['counts']
    denominator = 2*count['tp'] + count['fp'] + count['fn'] + count['abstained_negative']
    return {'f1': 2*count['tp']/denominator if denominator else None,
            'negative_abstention_penalty': count['abstained_negative'],
            'interpretation': 'pessimistic penalty sensitivity; these are not confirmed false positives'}


def evaluate():
    ensure_data()
    native_rows, audit = export_securify()
    native = {(r['view'], r['runtime_sha256']): r for r in native_rows}
    released = rows(SOURCE / 'dataset/labels.jsonl')
    withdrawal = rows(SOURCE / 'withdrawal-view-v02/labels.jsonl')
    common = set(read(SOURCE / 'common-cohort.json')['runtime_sha256'])
    eligible = {v: {r['runtime_sha256'] for r in native_rows if r['view'] == v} for v in ['released', 'withdrawal']}
    specs = {
        'common': ([r for r in released if r['runtime_sha256'] in common], COMMON, 'released'),
        'census': (released, INTERNAL, 'released'),
        'additional': ([r for r in released if not r['source_family_overlaps_development']], INTERNAL, 'released'),
        'withdrawal': (withdrawal, WITHDRAWAL, 'withdrawal'),
        'withdrawal-compatible': ([r for r in withdrawal if r['runtime_sha256'] in eligible['withdrawal']], WITHDRAWAL[:-1] + ['securify2', 'withdrawal-full'], 'withdrawal'),
        'released-compatible': ([r for r in released if r['runtime_sha256'] in eligible['released']], COMMON[:-1] + ['securify2', 'released-full'], 'released'),
    }
    for name in ['natural', 'injected']:
        subset = [r for r in withdrawal if ('SolidiFI' in r['providers']) == (name == 'injected')]
        specs['withdrawal-' + name] = (subset, WITHDRAWAL, 'withdrawal')
        specs['withdrawal-compatible-' + name] = ([r for r in subset if r['runtime_sha256'] in eligible['withdrawal']], WITHDRAWAL[:-1] + ['securify2', 'withdrawal-full'], 'withdrawal')
    tables = {}
    score = score_function()
    for name, (labels, methods, native_view) in specs.items():
        folder = HERE / 'results/views' / name
        folder.mkdir(parents=True, exist_ok=True)
        (folder / 'labels.jsonl').write_text(''.join(json.dumps(r, sort_keys=True) + '\n' for r in labels), encoding='utf8', newline='\n')
        metrics = {}
        for method in methods:
            p = predictions(labels, method, native, native_view)
            metric = score(labels, p, name + '/' + method)
            metric['comparison_limit'] = 'Only identical view/reference cells are compared; input representation and budgets differ as declared.'
            metric['conservative_sensitivity'] = conservative(metric)
            metrics[method] = metric
            (folder / (method + '-predictions.jsonl')).write_text(''.join(json.dumps(r, sort_keys=True) + '\n' for r in p), encoding='utf8', newline='\n')
        save(folder / 'metrics.json', metrics)
        tables[name] = metrics
    repeats = {}
    for view, labels in [('released', released), ('withdrawal', withdrawal)]:
        hashes = []
        for suffix in ['full', 'full-repeat-2', 'full-repeat-3']:
            p = predictions(labels, view + '-' + suffix, native, view)
            hashes.append(hashlib.sha256(json.dumps(p, sort_keys=True).encode()).hexdigest())
        repeats[view] = {'prediction_hashes': hashes, 'identical': len(set(hashes)) == 1}
    if not all(r['identical'] for r in repeats.values()):
        raise ValueError('Repeated full predictions differ')
    reasons = {}
    for name in ['common', 'census']:
        counts = Counter()
        for row in rows(HERE / 'results/views' / name / 'released-full-predictions.jsonl'):
            status = row['status']
            if status in {'positive', 'negative'}:
                continue
            group = 'preprocessing unavailable' if row.get('reason') == 'preprocessing unavailable' else 'capability gap' if status == 'unsupported' else status
            counts[group] += 1
        reasons[name] = dict(counts)
    result = {'schema': 'credential-integration/v06', 'views': tables, 'securify': audit,
              'repeatability': repeats, 'abstention_reasons': reasons,
              'bootstrap': read(SOURCE / 'evaluation/paired-bootstrap.json'),
              'method_changed': True, 'reference_changed': False}
    save(HERE / 'results/tables.json', result)
    print(json.dumps({'securify': audit, 'compatible_withdrawal': {
        k: {'f1': v['primary_end_to_end']['f1'], 'coverage': v['primary_end_to_end']['decisive_coverage'],
            'counts': v['primary_end_to_end']['counts']} for k, v in tables['withdrawal-compatible'].items()},
        'repeatability': repeats, 'abstention_reasons': reasons}, indent=2))
    return result


if __name__ == '__main__':
    raise SystemExit('Use python reproduce.py results to regenerate outputs beneath runs/ without changing fixed evidence.')
