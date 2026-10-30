"""Regression checks for the observed nested-verdict and stale-result export defects."""
import copy
import hashlib
import unittest
import evaluation as e


class NativeExportTests(unittest.TestCase):
    def pattern(self, kind='VIOLATION', contract='Vault'):
        return {'matches': [{'type': kind, 'locations': [{'contract': contract}], 'comments': []}]}

    def request(self):
        return {'source': 'contract Vault {}', 'source_sha256': hashlib.sha256(b'contract Vault {}').hexdigest(),
                'compiler_version': '0.5.17', 'target_scope': ['Vault']}

    def result(self):
        request = self.request()
        return {**{k: request[k] for k in ['source_sha256', 'compiler_version', 'target_scope']},
                'status': 'actual_analysis_completed',
                'patterns': [{'pattern': name, **self.pattern()} for name in e.MAPPING]}

    def test_nested_native_matches_without_top_level_verdict_are_positive(self):
        decoded = e.decode_native(self.request(), {'status': 'ok'}, self.result())
        self.assertEqual({p['status'] for p in decoded['properties'].values()}, {'positive'})

    def test_stale_positive_result_cannot_rescue_timeout_or_error(self):
        for status in ['timeout', 'error']:
            with self.subTest(status=status):
                actual = e.decode_native(self.request(), {'status': status}, self.result())
                self.assertEqual(actual['status'], status)
                self.assertEqual(actual['properties'], {})
                self.assertTrue(actual['stale_result_present'])

    def test_warning_is_unknown_and_scoped_violation_dominates(self):
        pattern = self.pattern('WARNING')
        self.assertEqual(e.classify_pattern(pattern, {'Vault'})['status'], 'unknown')
        pattern['matches'] += self.pattern()['matches']
        self.assertEqual(e.classify_pattern(pattern, {'Vault'})['status'], 'positive')

    def test_unrelated_contract_does_not_create_target_alarm(self):
        actual = e.classify_pattern(self.pattern(contract='Other'), {'Vault'})
        self.assertEqual(actual['status'], 'negative')
        self.assertEqual(actual['out_of_scope_matches'], 1)

    def test_missing_location_retains_uncertainty(self):
        pattern = self.pattern()
        pattern['matches'][0]['locations'] = []
        self.assertEqual(e.classify_pattern(pattern, {'Vault'})['status'], 'unknown')

    def test_source_or_configured_pattern_mismatch_is_rejected(self):
        result = self.result()
        result['source_sha256'] = 'wrong'
        with self.assertRaises(ValueError):
            e.decode_native(self.request(), {'status': 'ok'}, result)
        result = self.result()
        result['patterns'].pop()
        with self.assertRaises(ValueError):
            e.decode_native(self.request(), {'status': 'ok'}, result)


if __name__ == '__main__':
    unittest.main()
