"""v04 controls: path-complete ledger consumption, amount coverage, and the equality boundary of a limit.

Three groups, each differing in exactly one property of the program:

* `ledger_path_*` - the debit is conditional, unconditional, or guarded by a revert on the other path. Only the
  last two consume the ledger on every successful payment path.
* `ledger_amount_*` - the same-slot write subtracts the paid amount, nothing (`amount - amount`), half of it, or
  is undone afterwards. Only the first is a debit that covers the payment.
* `guard_equality_*` - `amount < balance` and `amount <= balance` both prevent an over-withdrawal, but they differ
  when the amount equals the balance, so both protect while only one admits the full balance.

The factories only build facts, so they can be imported by the regression tests, the defect-reproduction script
and the compiled-control cross-check.
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


def _pay(builder, amount_var: str, base: int = 0x500):
    gas = builder.stmt('0x%x' % (base + 0), 'CONST', defines=['0x%x' % (base + 0)], literal=0x8fc)
    caller = builder.stmt('0x%x' % (base + 1), 'CALLER', defines=['0x%x' % (base + 1)])
    offset = builder.stmt('0x%x' % (base + 2), 'CONST', defines=['0x%x' % (base + 2)], literal=0)
    builder.stmt('0x%x' % (base + 3), 'CALL',
                 uses=[gas, caller, amount_var, offset, offset, offset, offset],
                 defines=['0x%x' % (base + 3)])


def _read_balance(builder, prefix: str = '0x2'):
    caller = builder.stmt(prefix + '1', 'CALLER', uses=[], defines=[prefix + '1'])
    balance = builder.stmt(prefix + '2', 'SLOAD', uses=[caller], defines=[prefix + '2'])
    return caller, balance


def _flag(builder, prefix: str = '0x4'):
    """A branch condition that is neither an identity nor a limit guard."""
    slot = builder.stmt(prefix + '1', 'CONST', uses=[], defines=[prefix + '1'], literal=0x99)
    stored = builder.stmt(prefix + '2', 'SLOAD', uses=[slot], defines=[prefix + '2'])
    zero = builder.stmt(prefix + '3', 'CONST', uses=[], defines=[prefix + '3'], literal=0)
    return builder.stmt(prefix + '4', 'EQ', uses=[stored, zero], defines=[prefix + '4'])


def _zero(builder, identifier: str):
    return builder.stmt(identifier, 'CONST', uses=[], defines=[identifier], literal=0)


# --------------------------------------------------------------------------------------------------------
# Path completeness of the debit
# --------------------------------------------------------------------------------------------------------

def ledger_path_unconditional(directory: Path) -> Dict[str, object]:
    """Pay the recorded balance and clear it on the only continuation: consumed."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', [])
    _, balance = _read_balance(builder)
    _pay(builder, balance)
    builder.stmt('0x31', 'SSTORE', uses=['0x21', _zero(builder, '0x32')])
    builder.stmt('0x33', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'negative'}}


def ledger_path_optional(directory: Path) -> Dict[str, object]:
    """Pay, then clear only on one branch; the other branch completes without clearing: not consumed."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'])
    caller, balance = _read_balance(builder)
    _pay(builder, balance)
    condition = _flag(builder)
    builder.stmt('0x45', 'CONST', uses=[], defines=['0x45'], literal=0x20)
    builder.stmt('0x46', 'JUMPI', uses=['0x45', condition])
    builder.block('0x20', [])
    builder.stmt('0x21x', 'SSTORE', uses=[caller, _zero(builder, '0x22x')])
    builder.stmt('0x23x', 'STOP')
    builder.block('0x30', [])
    builder.stmt('0x31x', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'positive'}}


def ledger_path_guarded_clear(directory: Path) -> Dict[str, object]:
    """Pay, revert unless the flag holds, then clear: every completing path clears, so consumed."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'])
    caller, balance = _read_balance(builder)
    _pay(builder, balance)
    condition = _flag(builder)
    builder.stmt('0x45', 'CONST', uses=[], defines=['0x45'], literal=0x20)
    builder.stmt('0x46', 'JUMPI', uses=['0x45', condition])
    builder.block('0x20', [])
    builder.stmt('0x21x', 'SSTORE', uses=[caller, _zero(builder, '0x22x')])
    builder.stmt('0x23x', 'STOP')
    builder.block('0x30', [])
    zero = _zero(builder, '0x31x')
    builder.stmt('0x32x', 'REVERT', uses=[zero, zero])
    return {'facts': builder.emit(directory), 'expected': {'105': 'negative'}}


def ledger_path_clear_then_restore(directory: Path) -> Dict[str, object]:
    """Clear the slot and then write the paid amount back: the ledger ends up credited, so not consumed."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', [])
    caller, balance = _read_balance(builder)
    _pay(builder, balance)
    builder.stmt('0x31', 'SSTORE', uses=[caller, _zero(builder, '0x32')])
    builder.stmt('0x33', 'SSTORE', uses=[caller, balance])
    builder.stmt('0x34', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'positive'}}


# --------------------------------------------------------------------------------------------------------
# Amount coverage of the debit
# --------------------------------------------------------------------------------------------------------

def ledger_amount_exact(directory: Path) -> Dict[str, object]:
    """`balances[caller] = balances[caller] - amount`: a debit that covers what was paid."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', [])
    caller, balance = _read_balance(builder)
    _pay(builder, balance)
    again = builder.stmt('0x23', 'SLOAD', uses=[caller], defines=['0x23'])
    written = builder.stmt('0x24', 'SUB', uses=[again, balance], defines=['0x24'])
    builder.stmt('0x25', 'SSTORE', uses=[caller, written])
    builder.stmt('0x26', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'negative'}}


def ledger_amount_zero(directory: Path) -> Dict[str, object]:
    """`balances[caller] = old - (amount - amount)`: depends on the amount but subtracts nothing."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', [])
    caller, balance = _read_balance(builder)
    _pay(builder, balance)
    again = builder.stmt('0x23', 'SLOAD', uses=[caller], defines=['0x23'])
    nothing = builder.stmt('0x24', 'SUB', uses=[balance, balance], defines=['0x24'])
    written = builder.stmt('0x25', 'SUB', uses=[again, nothing], defines=['0x25'])
    builder.stmt('0x26', 'SSTORE', uses=[caller, written])
    builder.stmt('0x27', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'positive'}}


def ledger_amount_partial(directory: Path) -> Dict[str, object]:
    """`balances[caller] = old - amount / 2`: a debit that does not cover what was paid."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', [])
    caller, balance = _read_balance(builder)
    _pay(builder, balance)
    again = builder.stmt('0x23', 'SLOAD', uses=[caller], defines=['0x23'])
    two = builder.stmt('0x24', 'CONST', uses=[], defines=['0x24'], literal=2)
    half = builder.stmt('0x25', 'DIV', uses=[balance, two], defines=['0x25'])
    written = builder.stmt('0x26', 'SUB', uses=[again, half], defines=['0x26'])
    builder.stmt('0x27', 'SSTORE', uses=[caller, written])
    builder.stmt('0x28', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'positive'}}


def ledger_amount_clear(directory: Path) -> Dict[str, object]:
    """Pay the whole recorded balance and clear the slot: the supported full-balance clear."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', [])
    caller, balance = _read_balance(builder)
    _pay(builder, balance)
    builder.stmt('0x25', 'SSTORE', uses=[caller, _zero(builder, '0x26')])
    builder.stmt('0x27', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'negative'}}


def ledger_amount_clear_after_conditional(directory: Path) -> Dict[str, object]:
    """Clear before paying, with a branch afterwards that writes nothing to the slot: still consumed."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'])
    caller, balance = _read_balance(builder)
    builder.stmt('0x25', 'SSTORE', uses=[caller, _zero(builder, '0x26')])
    _pay(builder, balance)
    condition = _flag(builder)
    builder.stmt('0x45', 'CONST', uses=[], defines=['0x45'], literal=0x20)
    builder.stmt('0x46', 'JUMPI', uses=['0x45', condition])
    builder.block('0x20', [])
    builder.stmt('0x21x', 'STOP')
    builder.block('0x30', [])
    builder.stmt('0x31x', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'negative'}}


# --------------------------------------------------------------------------------------------------------
# The equality boundary of a limit
# --------------------------------------------------------------------------------------------------------

def _limit_layout(directory: Path, *, op: str, operands: Tuple[str, str], negated: bool,
                  payment_on_true: bool) -> Dict[str, object]:
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
    builder.stmt('0x26', 'CONST', uses=[], defines=['0x26'],
                 literal=0x30 if payment_on_true else 0x20)
    builder.stmt('0x27', 'JUMPI', uses=['0x26', tested])
    builder.block('0x20', [])
    zero = builder.stmt('0x28', 'CONST', uses=[], defines=['0x28'], literal=0)
    builder.stmt('0x29', 'REVERT', uses=[zero, zero])
    builder.block('0x30', [])
    _pay(builder, amount)
    builder.stmt('0x2a', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'negative'}}


def guard_equality_inclusive(directory: Path) -> Dict[str, object]:
    """`require(amount <= balance)` compiled as the over-withdrawal test: the full balance is allowed."""
    return _limit_layout(directory, op='LT', operands=('balance', 'amount'), negated=False,
                         payment_on_true=False)


def guard_equality_inclusive_negated(directory: Path) -> Dict[str, object]:
    """The same inclusive limit as `ISZERO(balance < amount)`: the full balance is allowed."""
    return _limit_layout(directory, op='LT', operands=('balance', 'amount'), negated=True,
                         payment_on_true=True)


def guard_equality_strict(directory: Path) -> Dict[str, object]:
    """`require(amount < balance)`: also prevents an over-withdrawal, but rejects the full balance."""
    return _limit_layout(directory, op='LT', operands=('amount', 'balance'), negated=False,
                         payment_on_true=True)


def guard_equality_strict_gt(directory: Path) -> Dict[str, object]:
    """`require(balance > amount)`: the strict form written with the comparison reversed."""
    return _limit_layout(directory, op='GT', operands=('balance', 'amount'), negated=False,
                         payment_on_true=True)


CONTROLS = {
    'ledger_path_unconditional': ledger_path_unconditional,
    'ledger_path_optional': ledger_path_optional,
    'ledger_path_guarded_clear': ledger_path_guarded_clear,
    'ledger_path_clear_then_restore': ledger_path_clear_then_restore,
    'ledger_amount_exact': ledger_amount_exact,
    'ledger_amount_zero': ledger_amount_zero,
    'ledger_amount_partial': ledger_amount_partial,
    'ledger_amount_clear': ledger_amount_clear,
    'ledger_amount_clear_after_conditional': ledger_amount_clear_after_conditional,
    'guard_equality_inclusive': guard_equality_inclusive,
    'guard_equality_inclusive_negated': guard_equality_inclusive_negated,
    'guard_equality_strict': guard_equality_strict,
    'guard_equality_strict_gt': guard_equality_strict_gt,
}


def build_all(root: Path) -> List[Tuple[str, Path, Dict[str, str]]]:
    rows = []
    for name, factory in CONTROLS.items():
        directory = Path(root) / name
        result = factory(directory)
        rows.append((name, result['facts'], result.get('expected', {})))
    return rows
