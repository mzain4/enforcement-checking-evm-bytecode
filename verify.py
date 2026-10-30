"""Read-only integrity, raw-output and independent arithmetic verification.

Run from any directory. MANIFEST.json covers the implementation, experiments and publication material.
This does not re-execute the external detectors or the frontend.
"""
from pathlib import Path
from collections import Counter
import argparse
import hashlib
import json
import evaluation as e


def close(a, b):
    return a is None and b is None or isinstance(a, (int, float)) and isinstance(b, (int, float)) and abs(a-b) < 1e-12


def independent(labels, predictions):
    by_id = {r['case_id']: r for r in predictions}
    if len(by_id) != len(predictions) or set(by_id) != {r['case_id'] for r in labels}:
        raise ValueError('Duplicate or mismatched prediction population')
    def count(subset):
        c = Counter()
        statuses = Counter()
        for row in subset:
            status = by_id[row['case_id']]['status']
            statuses[status] += 1
            truth = row['vulnerable']
            if truth is None:
                c['unresolved_reference'] += 1
                continue
            c['known_positive' if truth else 'known_negative'] += 1
            if status == 'positive':
                c['tp' if truth else 'fp'] += 1
            elif status == 'negative':
                c['fn' if truth else 'tn'] += 1
            elif truth:
                c['fn'] += 1
                c['abstained_positive'] += 1
            else:
                c['abstained_negative'] += 1
        tp, fp, fn = (c[k] for k in ['tp', 'fp', 'fn'])
        denominator = 2*tp+fp+fn
        return {'counts': {k: c[k] for k in ['tp','fp','fn','tn','known_positive','known_negative','abstained_positive','abstained_negative','unresolved_reference']},
                'precision': tp/(tp+fp) if tp+fp else None,
                'recall': tp/(tp+fn) if tp+fn else None,
                'f1': 2*tp/denominator if denominator else None,
                'decisive_coverage': (statuses['positive']+statuses['negative'])/len(subset),
                'prediction_statuses': dict(statuses)}
    overall = count(labels)
    categories = {swc: count([r for r in labels if r['swc'] == swc]) for swc in sorted({r['swc'] for r in labels})}
    return overall, categories


def verify():
    problems = []
    from artifact_data import verify_data
    evidence = verify_data()
    problems.extend(evidence['problems'])
    from verify_correction import verify_correction
    correction = verify_correction()
    problems.extend(correction['problems'])
    manifest = e.HERE / 'MANIFEST.json'
    hashes = 0
    if manifest.exists():
        for name, expected in e.read(manifest)['files'].items():
            path = e.HERE / name
            if not path.is_file() or e.sha(path) != expected:
                problems.append('file identity: ' + name)
            hashes += 1
    tables = e.read(e.HERE / 'results/tables.json')
    statuses_checked = 0
    cells_checked = 0
    methods_checked = 0
    for view, metrics in tables['views'].items():
        folder = e.HERE / 'results/views' / view
        labels = e.rows(folder / 'labels.jsonl')
        label_by_id = {r['case_id']: r for r in labels}
        for method, metric in metrics.items():
            predictions = e.rows(folder / (method + '-predictions.jsonl'))
            overall, categories = independent(labels, predictions)
            methods_checked += 1
            cells_checked += len(labels)
            if overall != metric['primary_end_to_end']:
                problems.append(view + '/' + method + ': independent pooled arithmetic differs')
            if categories != metric['by_swc']:
                problems.append(view + '/' + method + ': independent category arithmetic differs')
            macro = sum(c['f1'] or 0 for c in categories.values()) / len(categories)
            if not close(macro, metric['macro_f1']):
                problems.append(view + '/' + method + ': macro differs')
            c = overall['counts']
            denominator = 2*c['tp']+c['fp']+c['fn']+c['abstained_negative']
            lower = 2*c['tp']/denominator if denominator else None
            if not close(lower, metric['conservative_sensitivity']['f1']):
                problems.append(view + '/' + method + ': sensitivity differs')
            for prediction in predictions:
                if method.startswith('all-'):
                    continue
                label = label_by_id[prediction['case_id']]
                if method == 'securify2':
                    native_view = 'withdrawal' if view.startswith('withdrawal') else 'released'
                    record = e.read(e.HERE / 'results/securify' / native_view / (label['runtime_sha256'] + '.json'))
                else:
                    record = e.raw_record(method, label['runtime_sha256'])
                result = record.get('result', record)
                status = result.get('properties', {}).get(label['swc'], {}).get('status', result.get('status', 'error'))
                if status != prediction['status']:
                    problems.append(view + '/' + method + ': raw decision differs: ' + prediction['case_id'])
                statuses_checked += 1
    facts = 0
    reference_consensuses = 0
    for view in ['dataset', 'withdrawal-view-v02']:
        for label in e.rows(e.SOURCE / view / 'labels.jsonl'):
            assessments = label.get('all_cgt_assessments', label.get('assessments', []))
            values = {r['property_holds'] == 't' for r in assessments}
            expected = next(iter(values)) if len(values) == 1 else None
            if not assessments or label['vulnerable'] != expected:
                problems.append('provider assessment consensus: ' + label['case_id'])
            reference_consensuses += 1
        for item in e.rows(e.SOURCE / view / 'inputs.jsonl'):
            identity = item['runtime_sha256']
            folder = e.SOURCE / view / 'facts' / identity
            if not folder.is_dir():
                continue
            raw = bytes.fromhex(''.join((folder / 'bytecode.hex').read_text().split()).removeprefix('0x'))
            if hashlib.sha256(raw).hexdigest() != identity:
                problems.append('facts/runtime identity: ' + identity)
            facts += 1
    if tables['securify']['native_matches_in_successful_runs'].get('VIOLATION') != 688:
        problems.append('nested native verdict regression')
    if len(tables['securify']['stale_result_files_ignored']) != 3:
        problems.append('stale-result accounting differs')
    if not all(r['identical'] for r in tables['repeatability'].values()):
        problems.append('full repeat files differ')
    result = {'problems': problems, 'passed': not problems, 'views': len(tables['views']),
              'method_views': methods_checked, 'reference_cell_comparisons': cells_checked,
              'raw_statuses_checked': statuses_checked, 'facts_runtime_identities_checked': facts,
              'provider_reference_consensuses_checked': reference_consensuses,
              'manifest_files_checked': hashes, 'evidence_files_checked': evidence['files'],
              'scope': 'hashes, saved-output correspondence and independently recomputed scores; native tools/frontend not re-executed'}
    print(json.dumps(result, indent=2))
    return result


if __name__ == '__main__':
    raise SystemExit(0 if verify()['passed'] else 1)
