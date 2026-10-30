"""Regenerate scores and publication exports without changing fixed evidence."""
from pathlib import Path
import json
import shutil
import tempfile
import evaluation as e

ROOT = Path(__file__).resolve().parent


def main():
    (ROOT / 'runs').mkdir(exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix='results-', dir=ROOT / 'runs'))
    (out / 'support').mkdir()
    shutil.copy2(ROOT / 'support/frozen_scorer.py', out / 'support/frozen_scorer.py')
    shutil.copytree(ROOT / 'results/diagnostics', out / 'results/diagnostics')
    expected = e.read(ROOT / 'results/tables.json')
    e.HERE = out
    e.SOURCE = ROOT / 'experiments'
    actual = e.evaluate()
    differences = []
    def equivalent(a, b, path='tables'):
        if isinstance(a, float) and isinstance(b, float):
            if abs(a - b) > 1e-12:
                differences.append(path)
        elif isinstance(a, dict) and isinstance(b, dict) and a.keys() == b.keys():
            for key in a:
                equivalent(a[key], b[key], path + '/' + key)
        elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
            for index, (x, y) in enumerate(zip(a, b)):
                equivalent(x, y, path + '/' + str(index))
        elif type(a) is not type(b) or a != b:
            differences.append(path)
    equivalent(actual, expected)
    e.save(out / 'comparison.json', {'passed': not differences,
        'absolute_float_tolerance': 1e-12, 'output': str(out),
        'fixed_evidence_modified': False, 'views': len(actual['views']),
        'differences': differences})
    if differences:
        raise ValueError('Regenerated results differ: ' + str(differences[:10]))
    print(json.dumps({'passed': True, 'views': len(actual['views']),
                      'output': str(out), 'fixed_evidence_modified': False}, indent=2))


if __name__ == '__main__':
    main()
