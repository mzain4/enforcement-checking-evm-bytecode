"""Export a new run against fixed references, after label-free detection has ended."""
from pathlib import Path
import argparse
import json
import evaluation as e


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', help='Run name beneath runs/')
    args = parser.parse_args()
    folder = (e.HERE / 'runs' / args.run).resolve()
    if not folder.is_relative_to((e.HERE / 'runs').resolve()):
        parser.error('Run must be beneath runs/')
    config = e.read(folder / 'configuration.json')
    view = config['view']
    data = e.SOURCE / ('dataset' if view == 'released' else 'withdrawal-view-v02')
    labels = e.rows(data / 'labels.jsonl')
    if config.get('profile') == 'common':
        wanted = set(e.read(e.SOURCE / 'common-cohort.json')['runtime_sha256'])
        labels = [r for r in labels if r['runtime_sha256'] in wanted]
    predictions = []
    mismatches = []
    method = ('released-' if view == 'released' else 'withdrawal-') + config['method']
    for label in labels:
        record = e.read(folder / 'runs' / (label['runtime_sha256'] + '.json'))
        actual = record.get('result', record)
        status = actual.get('properties', {}).get(label['swc'], {}).get('status', actual.get('status', 'error'))
        prior = e.raw_record(method, label['runtime_sha256'])
        result = prior.get('result', prior)
        expected = result.get('properties', {}).get(label['swc'], {}).get('status', result.get('status', 'error'))
        if expected != status:
            mismatches.append({'case_id': label['case_id'], 'expected': expected, 'actual': status})
        predictions.append({'case_id': label['case_id'], 'property': label['swc'], 'status': status})
    metrics = e.score_function()(labels, predictions, args.run)
    (folder / 'predictions.jsonl').write_text(''.join(json.dumps(r, sort_keys=True) + '\n' for r in predictions))
    e.save(folder / 'metrics.json', metrics)
    summary = {'passed': not mismatches, 'view': view, 'profile': config.get('profile', 'all'),
               'method': config['method'], 'cells': len(labels), 'differences': mismatches,
               'f1': metrics['primary_end_to_end']['f1'], 'macro_f1': metrics['macro_f1']}
    e.save(folder / 'comparison.json', summary)
    print(json.dumps(summary, indent=2))
    raise SystemExit(bool(mismatches))


if __name__ == '__main__':
    main()
