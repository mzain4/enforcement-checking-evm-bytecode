"""v03 controls: guard layout equivalence and ledger-slot identity.

Two reasoning components are exercised here rather than by example-specific exceptions:

* `guard_layout_*` - one property, `require(amount <= balance)`, written five ways (LT/GT, negated, swapped
  branch targets). Every layout must reach the *same* verdict, and the two inverted layouts must reach the
  opposite one.
* `ledger_*` - one withdrawal shape, differing only in which slot is written and with which value. Only a
  matching-slot debit (cleared to zero or decremented by the amount) may count as consumption.

The factories only build facts, so they can be imported by the regression tests, the defect-reproduction
script and the compiled-control cross-check.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Tuple

try:                                                     # a rule package placed first on sys.path
    from enforcement_next.controls import FactsBuilder
except ModuleNotFoundError:                              # the ordinary repository layout
    from implementation.enforcement_next.controls import FactsBuilder


def _dispatcher(builder: FactsBuilder):
    builder.function('__function_selector__', '0x00000000')
    builder.block('0x1', [])
    builder.stmt('0x2', 'STOP')


def _withdraw_call(builder, amount_var: str, base: int = 0x800):
    gas = builder.stmt('0x%x' % (base + 0), 'CONST', defines=['0x%x' % (base + 0)], literal=0x8fc)
    caller = builder.stmt('0x%x' % (base + 1), 'CALLER', defines=['0x%x' % (base + 1)])
    offset = builder.stmt('0x%x' % (base + 2), 'CONST', defines=['0x%x' % (base + 2)], literal=0)
    builder.stmt('0x%x' % (base + 3), 'CALL',
                 uses=[gas, caller, amount_var, offset, offset, offset, offset],
                 defines=['0x%x' % (base + 3)])
    builder.stmt('0x%x' % (base + 4), 'STOP')


def _guard_layout(directory: Path, *, op: str, operands: Tuple[str, str], negated: bool,
                  payment_on_true: bool, swc: str = '105') -> Dict[str, object]:
    """`require(amount <= balances[caller])` in one of its equivalent compilations, then the withdrawal.

    `op`/`operands` build the tested relation, `negated` wraps it in ISZERO, and `payment_on_true` says whether
    the jump target of a true condition is the payment block (the guard `require`s the limit) or the revert
    block (the guard `require`s the complementary condition).
    """
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'])
    caller = builder.stmt('0x21', 'CALLER', uses=[], defines=['0x21'])
    balance = builder.stmt('0x22', 'SLOAD', uses=[caller], defines=['0x22'])
    amount = builder.stmt('0x23', 'CALLDATALOAD', uses=[], defines=['0x23'])
    operands = [balance if name == 'balance' else amount for name in operands]
    condition = builder.stmt('0x24', op, uses=operands, defines=['0x24'])
    tested = condition
    if negated:
        tested = builder.stmt('0x25', 'ISZERO', uses=[condition], defines=['0x25'])
    target_block = 0x30 if payment_on_true else 0x20
    builder.stmt('0x26', 'CONST', uses=[], defines=['0x26'], literal=target_block)
    builder.stmt('0x27', 'JUMPI', uses=['0x26', tested])
    builder.block('0x20', [])
    zero = builder.stmt('0x28', 'CONST', uses=[], defines=['0x28'], literal=0)
    builder.stmt('0x29', 'REVERT', uses=[zero, zero])
    builder.block('0x30', [])
    _withdraw_call(builder, amount)
    return {'facts': builder.emit(directory), 'expected': {swc: 'negative'}}


def guard_layout_jump_to_payment(directory: Path) -> Dict[str, object]:
    """`JUMPI(balance < amount, revert, payment)`: the classic `require(amount <= balance)`."""
    return _guard_layout(directory, op='LT', operands=('balance', 'amount'), negated=False,
                         payment_on_true=False)


def guard_layout_jump_to_payment_negated(directory: Path) -> Dict[str, object]:
    """`JUMPI(ISZERO(balance < amount), payment, revert)`: the same limit, payment on the true edge."""
    return _guard_layout(directory, op='LT', operands=('balance', 'amount'), negated=True,
                         payment_on_true=True)


def guard_layout_jump_to_payment_gt(directory: Path) -> Dict[str, object]:
    """`JUMPI(amount > balance, revert, payment)`: the same limit written with the reversed comparison."""
    return _guard_layout(directory, op='GT', operands=('amount', 'balance'), negated=False,
                         payment_on_true=False)


def guard_layout_jump_to_payment_swapped(directory: Path) -> Dict[str, object]:
    """`JUMPI(amount < balance, payment, revert)`: the strict form, payment on the true edge."""
    return _guard_layout(directory, op='LT', operands=('amount', 'balance'), negated=False,
                         payment_on_true=True)


def guard_layout_jump_to_payment_swapped_gt(directory: Path) -> Dict[str, object]:
    """`JUMPI(balance > amount, payment, revert)`: the strict form via GT, payment on the true edge."""
    return _guard_layout(directory, op='GT', operands=('balance', 'amount'), negated=False,
                         payment_on_true=True)


def guard_layout_inverted(directory: Path) -> Dict[str, object]:
    """`require(amount >= balance)`: not(amount < balance) rejects the safe case and admits an over-withdrawal."""
    result = _guard_layout(directory, op='LT', operands=('amount', 'balance'), negated=True,
                           payment_on_true=False)
    result['expected'] = {'105': 'positive'}
    return result


def guard_layout_inverted_swapped(directory: Path) -> Dict[str, object]:
    """`JUMPI(amount < balance, revert, payment)`: rejects the safe case, so it protects nothing."""
    result = _guard_layout(directory, op='LT', operands=('amount', 'balance'), negated=False,
                           payment_on_true=False)
    result['expected'] = {'105': 'positive'}
    return result


# --------------------------------------------------------------------------------------------------------
# Ledger-slot identity
# --------------------------------------------------------------------------------------------------------

def _ledger(directory: Path, *, write_slot: str, write_amount: str,
            separate_branch: bool = False) -> Dict[str, object]:
    """Read `balances[caller]`, pay exactly that amount to the caller, then update one storage slot.

    `write_slot` is `same` (the slot the amount was read from) or `next` (`caller + 1`), and `write_amount`
    is `zero`, `unchanged`, `credit` (`old + amount`) or `debit` (`old - amount`).
    """
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'] if separate_branch else [])
    caller = builder.stmt('0x21', 'CALLER', uses=[], defines=['0x21'])
    balance = builder.stmt('0x22', 'SLOAD', uses=[caller], defines=['0x22'])
    if not separate_branch:
        gas = builder.stmt('0x23', 'CONST', defines=['0x23'], literal=0x8fc)
        offset = builder.stmt('0x24', 'CONST', defines=['0x24'], literal=0)
        builder.stmt('0x25', 'CALL', uses=[gas, caller, balance, offset, offset, offset, offset],
                     defines=['0x25'])
    slot = caller
    if write_slot == 'next':
        one = builder.stmt('0x26', 'CONST', uses=[], defines=['0x26'], literal=1)
        slot = builder.stmt('0x27', 'ADD', uses=[caller, one], defines=['0x27'])
    written: str
    if write_amount == 'zero':
        written = builder.stmt('0x31', 'CONST', uses=[], defines=['0x31'], literal=0)
    elif write_amount == 'unchanged':
        again = builder.stmt('0x32', 'SLOAD', uses=[slot], defines=['0x32'])
        written = again
    elif write_amount == 'credit':
        again = builder.stmt('0x33', 'SLOAD', uses=[slot], defines=['0x33'])
        written = builder.stmt('0x34', 'ADD', uses=[again, balance], defines=['0x34'])
    elif write_amount == 'debit':
        again = builder.stmt('0x35', 'SLOAD', uses=[slot], defines=['0x35'])
        written = builder.stmt('0x36', 'SUB', uses=[again, balance], defines=['0x36'])
    else:
        raise ValueError(write_amount)
    if separate_branch:
        # A flag branch that is neither an identity nor a limit guard, so the control tests only the ledger
        # path requirement: the zero write sits on the branch the transfer never joins.
        slot0 = builder.stmt('0x28', 'CONST', uses=[], defines=['0x28'], literal=0x99)
        stored = builder.stmt('0x29', 'SLOAD', uses=[slot0], defines=['0x29'])
        zero_c = builder.stmt('0x2a', 'CONST', uses=[], defines=['0x2a'], literal=0)
        flag = builder.stmt('0x2b', 'EQ', uses=[stored, zero_c], defines=['0x2b'])
        target = builder.stmt('0x2c', 'CONST', uses=[], defines=['0x2c'], literal=0x20)
        builder.stmt('0x2d', 'JUMPI', uses=[target, flag])
        builder.block('0x20', [])
        builder.stmt('0x37', 'SSTORE', uses=[slot, written])
        builder.stmt('0x38', 'STOP')
        builder.block('0x30', [])
        _withdraw_call(builder, balance)
    else:
        builder.stmt('0x37', 'SSTORE', uses=[slot, written])
        builder.stmt('0x38', 'STOP')
    return {'facts': builder.emit(directory)}


def ledger_unrelated_slot_zero(directory: Path) -> Dict[str, object]:
    """Write zero to `balances[caller + 1]`: a caller-keyed write to a different slot is not consumption."""
    result = _ledger(directory, write_slot='next', write_amount='zero')
    result['expected'] = {'105': 'positive'}
    return result


def ledger_same_slot_zero(directory: Path) -> Dict[str, object]:
    """Clear `balances[caller]` after paying the whole balance: a legitimate full-balance clear."""
    result = _ledger(directory, write_slot='same', write_amount='zero')
    result['expected'] = {'105': 'negative'}
    return result


def ledger_same_slot_debit(directory: Path) -> Dict[str, object]:
    """`balances[caller] -= amount`: a genuine debit of the amount that was paid."""
    result = _ledger(directory, write_slot='same', write_amount='debit')
    result['expected'] = {'105': 'negative'}
    return result


def ledger_same_slot_credit(directory: Path) -> Dict[str, object]:
    """`balances[caller] += amount`: the ledger grows, so the transfer is not debited."""
    result = _ledger(directory, write_slot='same', write_amount='credit')
    result['expected'] = {'105': 'positive'}
    return result


def ledger_same_slot_unchanged(directory: Path) -> Dict[str, object]:
    """Write the slot back unchanged: a write with no consumption."""
    result = _ledger(directory, write_slot='same', write_amount='unchanged')
    result['expected'] = {'105': 'positive'}
    return result


def ledger_off_path_zero(directory: Path) -> Dict[str, object]:
    """A same-slot zero write on a branch the transfer never shares: not on the relevant path."""
    result = _ledger(directory, write_slot='same', write_amount='zero', separate_branch=True)
    result['expected'] = {'105': 'positive'}
    return result


def ledger_next_slot_debit(directory: Path) -> Dict[str, object]:
    """Debit `balances[caller + 1]` while paying the balance read from `balances[caller]`: wrong slot."""
    result = _ledger(directory, write_slot='next', write_amount='debit')
    result['expected'] = {'105': 'positive'}
    return result


CONTROLS = {
    'guard_layout_jump_to_payment': guard_layout_jump_to_payment,
    'guard_layout_jump_to_payment_negated': guard_layout_jump_to_payment_negated,
    'guard_layout_jump_to_payment_gt': guard_layout_jump_to_payment_gt,
    'guard_layout_jump_to_payment_swapped': guard_layout_jump_to_payment_swapped,
    'guard_layout_jump_to_payment_swapped_gt': guard_layout_jump_to_payment_swapped_gt,
    'guard_layout_inverted': guard_layout_inverted,
    'guard_layout_inverted_swapped': guard_layout_inverted_swapped,
    'ledger_unrelated_slot_zero': ledger_unrelated_slot_zero,
    'ledger_same_slot_zero': ledger_same_slot_zero,
    'ledger_same_slot_debit': ledger_same_slot_debit,
    'ledger_same_slot_credit': ledger_same_slot_credit,
    'ledger_same_slot_unchanged': ledger_same_slot_unchanged,
    'ledger_off_path_zero': ledger_off_path_zero,
    'ledger_next_slot_debit': ledger_next_slot_debit,
}


def build_all(root: Path) -> List[Tuple[str, Path, Dict[str, str]]]:
    rows = []
    for name, factory in CONTROLS.items():
        directory = Path(root) / name
        result = factory(directory)
        rows.append((name, result['facts'], result.get('expected', {})))
    return rows
