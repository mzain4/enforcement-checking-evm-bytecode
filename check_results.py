"""Check substantive comparisons against fixed experiment results; no manuscript required."""
import json
import evaluation as e


def check():
    problems = []
    data = e.read(e.HERE / 'results/tables.json')
    common = data['views']['common']
    full = common['released-full']
    assertions = {
        'common_full_highest_primary_pooled': all(full['primary_end_to_end']['f1'] >= r['primary_end_to_end']['f1'] for r in common.values()),
        'common_full_highest_primary_macro': all(full['macro_f1'] >= r['macro_f1'] for r in common.values()),
        'slither_wins_conservative_sensitivity': common['full-slither']['conservative_sensitivity']['f1'] > full['conservative_sensitivity']['f1'],
        'origin_full_f1_higher_but_recall_lower_than_presence': full['by_swc']['115']['f1'] > common['released-presence']['by_swc']['115']['f1'] and full['by_swc']['115']['recall'] < common['released-presence']['by_swc']['115']['recall'],
        'origin_presence_finds_seven': common['released-presence']['by_swc']['115']['counts']['tp'] == 7,
        'credential_recovers_two_positives_adds_one_fp': full['primary_end_to_end']['counts']['tp']-common['released-local']['primary_end_to_end']['counts']['tp'] == 2 and full['primary_end_to_end']['counts']['fp']-common['released-local']['primary_end_to_end']['counts']['fp'] == 1,
        'source_all_positive_beats_real_methods_on_62': all(data['views']['withdrawal']['all-positive']['primary_end_to_end']['f1'] > v['primary_end_to_end']['f1'] for k,v in data['views']['withdrawal'].items() if not k.startswith('all-')),
        'compatible_slither_exceeds_full': data['views']['withdrawal-compatible']['withdrawal-v02-slither']['primary_end_to_end']['f1'] > data['views']['withdrawal-compatible']['withdrawal-full']['primary_end_to_end']['f1'],
        'native_securify_688_nested_violations': data['securify']['native_matches_in_successful_runs']['VIOLATION'] == 688,
        'securify44_population': data['views']['withdrawal-compatible']['securify2']['cases'] == 44,
    }
    for arm in ['common-mythril-two-tx','released-local']:
        lo, hi = data['bootstrap']['contrasts']['released-full minus '+arm]['percentile_95_interval']
        assertions['conditional_interval_crosses_zero:'+arm] = lo <= 0 <= hi
    assertions['conditional_slither_interval_positive'] = data['bootstrap']['contrasts']['released-full minus full-slither']['percentile_95_interval'][0] > 0
    prior = common['released-no-membership']['primary_end_to_end']['counts']
    now = full['primary_end_to_end']['counts']
    assertions['membership_one_tp_no_new_fp'] = now['tp'] - prior['tp'] == 1 and now['fp'] == prior['fp']
    lo, hi = data['bootstrap']['contrasts']['released-full minus released-no-membership']['percentile_95_interval']
    assertions['membership_interval_includes_zero'] = lo <= 0 <= hi
    field = e.read(e.HERE/'results/diagnostics/field-precision-results.json')
    identity = e.read(e.HERE/'results/diagnostics/identity-results.json')
    assertions['two_field_mask_changes'] = len(field['changed_rows']) == 2 and all(
        r['field_sensitive'] == 'negative' and r['word_mask_coarsened'] == 'positive'
        for r in field['changed_rows'])
    assertions['identity_32_scenarios_96_executions_one_family'] = (
        identity['scenarios'] == 32 and identity['executions'] == 96
        and identity['authored_families'] == 1 and identity['passed']
        and all(r['identical'] for r in identity['records']))
    problems += ['false substantive assertion: '+key for key,value in assertions.items() if not value]
    result = {'passed': not problems, 'problems': problems, 'assertions': assertions}
    print(json.dumps(result, indent=2))
    return result


if __name__ == '__main__':
    raise SystemExit(not check()['passed'])
