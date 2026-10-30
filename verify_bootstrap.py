"""Regenerate the saved paired analysis from supplied public-reference predictions."""
import importlib.util
import json
import math
import sys
import evaluation as e


def main():
    spec = importlib.util.spec_from_file_location('paired_resampling', e.HERE/'support/paired_bootstrap.py')
    if spec is None or spec.loader is None:
        raise ImportError('Original resampling code unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    labels = e.rows(e.HERE/'results/views/common/labels.jsonl')
    predictions = {name:e.rows(e.HERE/'results/views/common'/(name+'-predictions.jsonl')) for name in e.COMMON}
    actual = module.bootstrap(labels, e.COMMON, predictions, repetitions=2000)
    expected = e.read(e.HERE/'results/tables.json')['bootstrap']
    # Python's floating-point summation changed after 3.11. Require identical structure,
    # seed and counts, with a tolerance far below the reported four decimal places.
    errors = []
    def equivalent(a, b):
        if isinstance(a, float) and isinstance(b, float):
            errors.append(abs(a - b))
            return math.isfinite(a) and math.isfinite(b) and abs(a - b) <= 1e-12
        if isinstance(a, dict) and isinstance(b, dict):
            return a.keys() == b.keys() and all(equivalent(a[k], b[k]) for k in a)
        if isinstance(a, list) and isinstance(b, list):
            return len(a) == len(b) and all(equivalent(x, y) for x, y in zip(a, b))
        return type(a) is type(b) and a == b
    passed = equivalent(actual, expected)
    result = {'passed': passed, 'repetitions': 2000,
              'bit_exact': actual == expected, 'absolute_float_tolerance': 1e-12,
              'maximum_float_difference': max(errors, default=0.0), 'python': sys.version.split()[0],
              'clusters': actual['source_runtime_connected_clusters'],
              'scope': 'paired conditional resampling regenerated; not a new detector experiment'}
    print(json.dumps(result, indent=2))
    return result['passed']


if __name__ == '__main__':
    raise SystemExit(0 if main() else 1)
