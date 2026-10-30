"""Evaluate the pre-declared mapping controls against baseline and candidate, and compare to expectations."""
from pathlib import Path
import json
import sys

W = Path(__file__).resolve().parents[1]
CONTROLS = W / 'controls/mapping'
ARMS = {'field-integrity': W / 'baselines/field-integrity', 'full': W}


def verdict(code_root, facts):
    for name in [n for n in list(sys.modules) if n == 'implementation' or n.startswith('implementation.')]:
        del sys.modules[name]
    sys.path.insert(0, str(code_root))
    try:
        from implementation.enforcement_state.analyze import analyse_facts
        result = analyse_facts(facts, credential_integrity=True)
    finally:
        sys.path.remove(str(code_root))
    return {'105': result['properties']['105']['status'],
            'reason': result['properties']['105'].get('reason'),
            'candidates': result.get('credential_candidates', []),
            'error': result.get('credential_analysis_error')}


def main():
    expectations = {k: v['expected'] for k, v in
                    json.loads((CONTROLS / 'expectations.json').read_text()).items()}
    results = {}
    ok = True
    for name, expected in expectations.items():
        facts = CONTROLS / name
        arms = {arm: verdict(root, facts) for arm, root in ARMS.items()}
        candidate = arms['full']['105']
        passed = candidate == expected
        ok = ok and passed
        results[name] = {'expected': expected, 'arms': arms, 'passed': passed}
        print('%-34s expected=%-8s baseline=%-8s candidate=%-8s %s'
              % (name, expected, arms['field-integrity']['105'], candidate, 'PASS' if passed else 'FAIL'))
        if arms['full']['error']:
            print('   candidate error:', arms['full']['error'])
    (W / 'controls/mapping-results.json').write_text(
        json.dumps({'passed': ok, 'results': results}, indent=2, sort_keys=True) + '\n', encoding='utf8')
    print('\nALL_CONTROLS_PASS' if ok else '\nCONTROL_FAILURE')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
