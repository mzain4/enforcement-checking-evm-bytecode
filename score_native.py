"""Score a fresh native run without passing references to the analyzer."""
from pathlib import Path
import argparse
import json
import evaluation as e


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('run', help='Run name beneath runs/')
    args = p.parse_args()
    folder = (e.HERE / 'runs' / args.run).resolve()
    if not folder.is_relative_to((e.HERE / 'runs').resolve()):
        p.error('Run must be beneath runs/')
    config = e.read(folder / 'configuration.json')
    view = config.get('view', 'withdrawal' if config.get('population') == 'withdrawal-v02' else 'released')
    data = e.SOURCE / ('withdrawal-view-v02' if view.startswith('withdrawal') else 'dataset')
    inputs = e.rows(data / 'inputs.jsonl')
    ids = {r['runtime_sha256'] for r in inputs}
    if config.get('profile') == 'common':
        ids &= set(e.read(e.SOURCE / 'common-cohort.json')['runtime_sha256'])
    if config['method'] == 'securify2':
        ids &= {r['runtime_sha256'] for r in config['requests']}
    labels = [r for r in e.rows(data / 'labels.jsonl') if r['runtime_sha256'] in ids]
    predictions = []
    for row in labels:
        path = folder / 'runs' / (row['runtime_sha256'] + '.json')
        record = e.read(path) if path.exists() else {'status': 'missing', 'properties': {}}
        result = record.get('result', record)
        prop = result.get('properties', {}).get(row['swc'], {})
        predictions.append({'case_id': row['case_id'], 'property': row['swc'],
                            'status': prop.get('status', result.get('status', 'error'))})
    metrics = e.score_function()(labels, predictions, args.run)
    metrics['conservative_sensitivity'] = e.conservative(metrics)
    e.save(folder / 'metrics.json', metrics)
    (folder / 'predictions.jsonl').write_text(''.join(json.dumps(r, sort_keys=True) + '\n' for r in predictions))
    print(json.dumps({'cells': len(labels), 'counts': metrics['primary_end_to_end']['counts'],
                      'f1': metrics['primary_end_to_end']['f1'], 'coverage': metrics['primary_end_to_end']['decisive_coverage']}, indent=2))


if __name__ == '__main__':
    main()
