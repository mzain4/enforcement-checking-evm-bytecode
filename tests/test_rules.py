"""Rule controls for implementation/enforcement_next, run with the project's unittest convention.

    python -m unittest discover -s tests -v

The controls are authored micro-programs, not CGT samples. Each pair below differs in exactly the semantic
dependency the rule claims to read.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from implementation.enforcement_next.analyze import analyse_facts          # noqa: E402
from implementation.enforcement_next.control_suite import CONTROLS        # noqa: E402

# Guard-layout, ledger-path and metamorphic controls share the same fixture factories.
for candidate in (ROOT / 'tests/controls',):
    for module_name in ('v03_controls', 'v04_controls', 'v05_controls'):
        if (candidate / (module_name + '.py')).is_file():
            if str(candidate) not in sys.path:
                sys.path.insert(0, str(candidate))
            module = __import__(module_name)
            CONTROLS = dict(CONTROLS, **module.CONTROLS)


class ControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls._temporary.name)
        cls.results = {}
        for name, factory in CONTROLS.items():
            built = factory(cls.root / name)
            cls.results[name] = (analyse_facts(built['facts']), built['expected'])

    @classmethod
    def tearDownClass(cls):
        cls._temporary.cleanup()

    def assert_property(self, control, swc):
        result, expected = self.results[control]
        self.assertIn(swc, expected, control + ' has no expectation for ' + swc)
        actual = result['properties'][swc]['status']
        self.assertEqual(actual, expected[swc],
                         '%s %s: expected %s, got %s (%s)' % (
                             control, swc, expected[swc], actual,
                             result['properties'][swc]['reason']))

    def test_104_ignored_result_is_positive(self):
        self.assert_property('104_ignored', '104')

    def test_104_rejected_failure_is_negative(self):
        self.assert_property('104_rejected', '104')

    def test_104_inverted_check_is_positive(self):
        self.assert_property('104_inverted', '104')

    def test_104_accepted_failure_is_positive(self):
        self.assert_property('104_accepted_failure', '104')

    def test_104_handled_failure_is_negative(self):
        self.assert_property('104_handled_failure', '104')

    def test_104_uncertain_jump_is_unknown(self):
        self.assert_property('104_uncertain_jump', '104')

    def test_115_origin_owner_is_positive(self):
        self.assert_property('115_origin_owner', '115')

    def test_115_origin_caller_is_negative(self):
        self.assert_property('115_origin_caller', '115')

    def test_115_log_only_is_negative(self):
        self.assert_property('115_log_only', '115')

    def test_105_unguarded_is_positive(self):
        self.assert_property('105_unguarded', '105')

    def test_105_guarded_is_negative(self):
        self.assert_property('105_guarded', '105')

    def test_105_guard_outside_the_transfer_is_positive(self):
        self.assert_property('105_guard_outside', '105')

    def test_105_zero_value_is_negative(self):
        self.assert_property('105_zero_value', '105')

    def test_105_self_bound_withdrawal_is_negative(self):
        self.assert_property('105_self_bound', '105')

    def test_105_forward_limit_is_negative(self):
        self.assert_property('105_forward_limit', '105')

    def test_105_inverted_limit_is_positive(self):
        self.assert_property('105_inverted_limit', '105')

    def test_105_pays_when_overdrawn_is_positive(self):
        self.assert_property('105_pays_when_overdrawn', '105')

    def test_protecting_guard_layouts_agree(self):
        """Every limit that prevents an over-withdrawal protects: inclusive and strict writings alike."""
        names = [name for name in self.results if name.startswith('guard_layout_')
                 and 'inverted' not in name]
        verdicts = {self.results[name][0]['properties']['105']['status'] for name in names}
        self.assertEqual(len(names), 5)
        self.assertEqual(verdicts, {'negative'},
                         'guard layouts disagree: ' + repr(
                             {name: self.results[name][0]['properties']['105']['status']
                              for name in sorted(names)}))

    def test_equality_boundary_layouts_all_protect(self):
        """`amount < balance` and `amount <= balance` differ at equality but both prevent over-withdrawal."""
        names = [name for name in self.results if name.startswith('guard_equality_')]
        self.assertEqual(len(names), 4)
        for name in names:
            self.assert_property(name, '105')

    def test_inverted_guard_layouts_are_positive(self):
        for name in ('guard_layout_inverted', 'guard_layout_inverted_swapped'):
            self.assert_property(name, '105')

    def test_ledger_slot_identity_and_direction(self):
        expected = {
            'ledger_same_slot_zero': 'negative',
            'ledger_same_slot_debit': 'negative',
            'ledger_unrelated_slot_zero': 'positive',
            'ledger_next_slot_debit': 'positive',
            'ledger_same_slot_credit': 'positive',
            'ledger_same_slot_unchanged': 'positive',
            'ledger_off_path_zero': 'positive',
        }
        for name, status in expected.items():
            self.assert_property(name, '105')
            result, _ = self.results[name]
            self.assertEqual(result['properties']['105']['status'], status, name)

    def test_metamorphic_block_split_preserves_the_ledger_verdict(self):
        """Splitting or merging blocks must not change the verdict: the same program is the same program."""
        pairs = [('ledger_metamorphic_consume_merged', 'ledger_metamorphic_consume_split'),
                 ('ledger_metamorphic_restore_after_merged', 'ledger_metamorphic_restore_after_split'),
                 ('ledger_metamorphic_restore_between_merged', 'ledger_metamorphic_restore_between_split'),
                 ('ledger_metamorphic_restore_one_branch_merged',
                  'ledger_metamorphic_restore_one_branch_split')]
        for merged, split in pairs:
            self.assert_property(merged, '105')
            self.assert_property(split, '105')
            merged_status = self.results[merged][0]['properties']['105']['status']
            split_status = self.results[split][0]['properties']['105']['status']
            self.assertEqual(merged_status, split_status,
                             '%s and %s disagree: %s vs %s' % (merged, split, merged_status, split_status))

    def test_cross_block_restoration_is_not_consumed(self):
        """A clear followed by a payment and a later restore leaves the balance payable, in any block layout."""
        for name in ('ledger_metamorphic_restore_after_merged', 'ledger_metamorphic_restore_after_split',
                     'ledger_metamorphic_restore_between_merged', 'ledger_metamorphic_restore_between_split',
                     'ledger_metamorphic_restore_one_branch_merged',
                     'ledger_metamorphic_restore_one_branch_split'):
            self.assertEqual(self.results[name][0]['properties']['105']['status'], 'positive', name)

    def test_cross_block_valid_consumption_is_still_consumed(self):
        """The same split that exposes a restoration must not turn a real debit into an unprotected withdrawal."""
        for name in ('ledger_metamorphic_consume_merged', 'ledger_metamorphic_consume_split'):
            self.assertEqual(self.results[name][0]['properties']['105']['status'], 'negative', name)

    def test_ledger_consumption_must_cover_every_completing_path(self):
        expected = {
            'ledger_path_unconditional': 'negative',
            'ledger_path_guarded_clear': 'negative',
            'ledger_amount_clear_after_conditional': 'negative',
            'ledger_path_optional': 'positive',
            'ledger_path_clear_then_restore': 'positive',
        }
        for name, status in expected.items():
            self.assert_property(name, '105')
            result, _ = self.results[name]
            self.assertEqual(result['properties']['105']['status'], status, name)

    def test_ledger_debit_must_cover_the_paid_amount(self):
        expected = {
            'ledger_amount_exact': 'negative',
            'ledger_amount_clear': 'negative',
            'ledger_amount_zero': 'positive',
            'ledger_amount_partial': 'positive',
        }
        for name, status in expected.items():
            self.assert_property(name, '105')
            result, _ = self.results[name]
            self.assertEqual(result['properties']['105']['status'], status, name)

    def test_105_constant_payment_is_positive(self):
        self.assert_property('105_constant_payment', '105')

    def test_104_mixed_failure_continuations_is_unknown(self):
        self.assert_property('104_mixed_continuations', '104')

    def test_104_equality_with_success_is_negative(self):
        self.assert_property('104_eq_one', '104')

    def test_104_equality_with_two_is_positive(self):
        self.assert_property('104_eq_two', '104')


class ArithmeticTests(unittest.TestCase):
    """Word semantics of the folder and the boolean reduction; each case is an EVM-level fact."""

    MAX = (1 << 256) - 1

    def fold(self, op, left, right):
        from types import SimpleNamespace
        statements = {'a': ('CONST', []), 'b': ('CONST', []), 'r': (op, ['a', 'b'])}
        from implementation.enforcement_next.tac import resolve_constant
        facts = SimpleNamespace(
            instructions={key: SimpleNamespace(id=key, op=value[0], uses=list(value[1]), defines=[key])
                          for key, value in statements.items()},
            constants={'a': left, 'b': right},
            directory=Path(tempfile.gettempdir()),
            _enforcement_next_literals={'a': left, 'b': right})
        return resolve_constant(facts, 'r')

    def test_add_wraps_at_256_bits(self):
        self.assertEqual(self.fold('ADD', self.MAX, 1), 0)

    def test_sub_wraps_at_256_bits(self):
        self.assertEqual(self.fold('SUB', 0, 1), self.MAX)

    def test_mul_wraps_at_256_bits(self):
        self.assertEqual(self.fold('MUL', 1 << 128, 1 << 128), 0)

    def test_shift_uses_the_first_operand_as_the_shift_amount(self):
        self.assertEqual(self.fold('SHR', 8, 0xFF00), 255)
        self.assertEqual(self.fold('SHL', 8, 0xFF), 0xFF00)

    def test_division_by_zero_is_zero(self):
        self.assertEqual(self.fold('DIV', 7, 0), 0)
        self.assertEqual(self.fold('MOD', 7, 0), 0)

    def test_exponent_uses_the_first_operand_as_the_base(self):
        self.assertEqual(self.fold('EXP', 2, 8), 256)

    def test_equality_with_a_non_binary_constant_is_false(self):
        from types import SimpleNamespace
        from implementation.enforcement_next.rules import _bool_form
        statements = {'seed': ('CALL', []), 'two': ('CONST', []), 'cmp': ('EQ', ['seed', 'two'])}
        facts = SimpleNamespace(
            instructions={key: SimpleNamespace(id=key, op=value[0], uses=list(value[1]), defines=[key])
                          for key, value in statements.items()},
            constants={'two': 2},
            directory=Path(tempfile.gettempdir()),
            _enforcement_next_literals={'two': 2})
        self.assertEqual(_bool_form(facts, 'cmp', 'seed'), ('const', 0))


if __name__ == '__main__':
    unittest.main()
