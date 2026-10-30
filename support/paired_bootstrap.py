"""Paired source-family bootstrap used for the reported comparisons."""
from collections import Counter, defaultdict
import random
SWCS = ["104", "105", "115"]

def source_clusters(labels):
    parent = {}
    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    def union(a, b):
        a, b = find(a), find(b)
        parent[max(a, b)] = min(a, b)
    for r in labels:
        identity = 'runtime:' + r['runtime_sha256']
        find(identity)
        for fp in r.get('source_family_fingerprints', r.get('source_families', [])):
            if fp:
                union(identity, 'source:' + fp)
    return {r['case_id']: find('runtime:' + r['runtime_sha256']) for r in labels}

def packed_counts(labels, preds, clusters):
    result = defaultdict(lambda: [[0, 0, 0] for _ in SWCS])
    for label, prediction in zip(labels, preds):
        if label.get('vulnerable') is None:
            continue
        c = result[clusters[label['case_id']]][SWCS.index(label['swc'])]
        positive = prediction['status'] == 'positive'
        if label['vulnerable']:
            c[0 if positive else 2] += 1
        elif positive:
            c[1] += 1
    return result

def f1(counts):
    a, b, c = counts
    return 2*a/(2*a+b+c) if 2*a+b+c else 0.0

def bootstrap(labels, arms, predictions_by_arm, repetitions=2000):
    clusters = source_clusters(labels)
    units = sorted(set(clusters.values()))
    packed = {arm: packed_counts(labels, predictions_by_arm[arm], clusters) for arm in arms}
    rng = random.Random(20261029)
    values = {arm: [] for arm in arms}
    for _ in range(repetitions):
        weights = Counter(rng.choices(units, k=len(units)))
        for arm in arms:
            total = [[0, 0, 0] for _ in SWCS]
            for unit, weight in weights.items():
                data = packed[arm].get(unit, [[0, 0, 0] for _ in SWCS])
                for i in range(3):
                    for j in range(3):
                        total[i][j] += weight * data[i][j]
            values[arm].append(sum(f1(c) for c in total)/3)
    full = 'released-full'
    contrasts = {}
    for arm in arms:
        if arm == full:
            continue
        delta = sorted(a-b for a, b in zip(values[full], values[arm]))
        contrasts[full + ' minus ' + arm] = {
            'percentile_95_interval': [delta[int(.025*(repetitions-1))], delta[int(.975*(repetitions-1))]],
            'interpretation': 'conditional source-family cluster bootstrap; no population or held-out generalization claim'}
    return {'seed': 20261029, 'repetitions': repetitions, 'source_runtime_connected_clusters': len(units),
            'unit': 'connected runtime/source-family groups using every available fp_sol2', 'contrasts': contrasts}
