"""v05 controls: metamorphic block split/merge pairs for ledger consumption and restoration.

Each pair is the *same* program split across basic blocks differently: the merged variant keeps every statement
in one block, the split variant spreads the same statements over three or four blocks joined by unconditional
successors. Behaviour is unchanged by the split, so every pair must receive one verdict. The pair order is
`*_merged` then `*_split`, and `PAIRS` records the grouping so a test can assert agreement directly.

Four behaviours are covered:

* `consume` - read the balance, clear the slot, pay, stop. The ledger is consumed on the only completing path.
* `restore_after` - read, clear, pay, then write the saved balance back. The payment can be repeated.
* `restore_between` - read, clear, restore, then pay. The debit is undone before the money leaves.
* `restore_one_branch` - read, clear, pay, then restore on one of the two successful continuations only.

The factories only build facts, so the regression tests, the defect-reproduction script and the compiled-control
cross-check can all import them.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List

try:                                                     # a rule package placed first on sys.path
    from enforcement_next.controls import FactsBuilder
except ModuleNotFoundError:                              # the ordinary repository layout
    from implementation.enforcement_next.controls import FactsBuilder

PAIRS = (
    ('consume', 'ledger_metamorphic_consume_merged', 'ledger_metamorphic_consume_split'),
    ('restore_after', 'ledger_metamorphic_restore_after_merged', 'ledger_metamorphic_restore_after_split'),
    ('restore_between', 'ledger_metamorphic_restore_between_merged',
     'ledger_metamorphic_restore_between_split'),
    ('restore_one_branch', 'ledger_metamorphic_restore_one_branch_merged',
     'ledger_metamorphic_restore_one_branch_split'),
)


def _dispatcher(builder: FactsBuilder):
    builder.function('__function_selector__', '0x00000000')
    builder.block('0x1', [])
    builder.stmt('0x2', 'STOP')


def _read_balance(builder):
    caller = builder.stmt('0x21', 'CALLER', uses=[], defines=['0x21'])
    balance = builder.stmt('0x22', 'SLOAD', uses=[caller], defines=['0x22'])
    return caller, balance


def _clear(builder, caller: str, identifier: str, zero_id: str):
    zero = builder.stmt(zero_id, 'CONST', uses=[], defines=[zero_id], literal=0)
    return builder.stmt(identifier, 'SSTORE', uses=[caller, zero])


def _restore(builder, caller: str, balance: str, identifier: str):
    return builder.stmt(identifier, 'SSTORE', uses=[caller, balance])


def _pay(builder, amount_var: str, base: int = 0x500):
    builder.stmt('0x%x' % (base + 0), 'CONST', uses=[], defines=['0x%x' % (base + 0)], literal=0x8fc)
    caller = builder.stmt('0x%x' % (base + 1), 'CALLER', uses=[], defines=['0x%x' % (base + 1)])
    offset = builder.stmt('0x%x' % (base + 2), 'CONST', uses=[], defines=['0x%x' % (base + 2)], literal=0)
    builder.stmt('0x%x' % (base + 3), 'CALL',
                 uses=['0x%x' % (base + 0), caller, amount_var, offset, offset, offset, offset],
                 defines=['0x%x' % (base + 3)])


def _flag(builder, prefix: str = '0x4'):
    """A branch condition that is neither an identity nor a limit guard."""
    slot = builder.stmt(prefix + '1', 'CONST', uses=[], defines=[prefix + '1'], literal=0x99)
    stored = builder.stmt(prefix + '2', 'SLOAD', uses=[slot], defines=[prefix + '2'])
    zero = builder.stmt(prefix + '3', 'CONST', uses=[], defines=[prefix + '3'], literal=0)
    return builder.stmt(prefix + '4', 'EQ', uses=[stored, zero], defines=[prefix + '4'])


def _branch(builder, true_target: str):
    condition = _flag(builder)
    builder.stmt('0x45', 'CONST', uses=[], defines=['0x45'], literal=int(true_target, 16))
    builder.stmt('0x46', 'JUMPI', uses=['0x45', condition])


# --------------------------------------------------------------------------------------------------------
# The same four behaviours, merged into one block and split across blocks
# --------------------------------------------------------------------------------------------------------

def ledger_metamorphic_consume_merged(directory: Path) -> Dict[str, object]:
    """Read the balance, clear it and pay, all in one block: consumed."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', [])
    caller, balance = _read_balance(builder)
    _clear(builder, caller, '0x31', '0x32')
    _pay(builder, balance)
    builder.stmt('0x33', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'negative'}}


def ledger_metamorphic_consume_split(directory: Path) -> Dict[str, object]:
    """The same program over three blocks: read and clear, pay, stop. Consumption is unchanged."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20'])
    caller, balance = _read_balance(builder)
    _clear(builder, caller, '0x31', '0x32')
    builder.block('0x20', ['0x30'])
    _pay(builder, balance)
    builder.block('0x30', [])
    builder.stmt('0x41', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'negative'}}


def ledger_metamorphic_restore_after_merged(directory: Path) -> Dict[str, object]:
    """Read, clear, pay, then write the saved balance back --- one block: not consumed."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', [])
    caller, balance = _read_balance(builder)
    _clear(builder, caller, '0x31', '0x32')
    _pay(builder, balance)
    _restore(builder, caller, balance, '0x33')
    builder.stmt('0x34', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'positive'}}


def ledger_metamorphic_restore_after_split(directory: Path) -> Dict[str, object]:
    """The same program with the restoration in a later block: the ledger is still restored."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20'])
    caller, balance = _read_balance(builder)
    _clear(builder, caller, '0x31', '0x32')
    builder.block('0x20', ['0x30'])
    _pay(builder, balance)
    builder.block('0x30', [])
    _restore(builder, caller, balance, '0x41')
    builder.stmt('0x42', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'positive'}}


def ledger_metamorphic_restore_between_merged(directory: Path) -> Dict[str, object]:
    """Read, clear, restore, then pay --- one block: the debit is undone before the payment."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', [])
    caller, balance = _read_balance(builder)
    _clear(builder, caller, '0x31', '0x32')
    _restore(builder, caller, balance, '0x33')
    _pay(builder, balance)
    builder.stmt('0x34', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'positive'}}


def ledger_metamorphic_restore_between_split(directory: Path) -> Dict[str, object]:
    """The same program with the restoration in a block between the debit and the payment."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x25'])
    caller, balance = _read_balance(builder)
    _clear(builder, caller, '0x31', '0x32')
    builder.block('0x25', ['0x20'])
    _restore(builder, caller, balance, '0x35')
    builder.block('0x20', [])
    _pay(builder, balance)
    builder.stmt('0x41', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'positive'}}


def ledger_metamorphic_restore_one_branch_merged(directory: Path) -> Dict[str, object]:
    """Read, clear, pay, then restore on one of two completing continuations --- one block layout."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'])
    caller, balance = _read_balance(builder)
    _clear(builder, caller, '0x31', '0x32')
    _pay(builder, balance)
    _branch(builder, '0x20')
    builder.block('0x20', [])
    _restore(builder, caller, balance, '0x21x')
    builder.stmt('0x22x', 'STOP')
    builder.block('0x30', [])
    builder.stmt('0x31x', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'positive'}}


def ledger_metamorphic_restore_one_branch_split(directory: Path) -> Dict[str, object]:
    """The same program with the payment and the branch in separate blocks."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x40'])
    caller, balance = _read_balance(builder)
    _clear(builder, caller, '0x31', '0x32')
    builder.block('0x40', ['0x50', '0x60'])
    _pay(builder, balance)
    _branch(builder, '0x50')
    builder.block('0x50', [])
    _restore(builder, caller, balance, '0x51x')
    builder.stmt('0x52x', 'STOP')
    builder.block('0x60', [])
    builder.stmt('0x61x', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'positive'}}


CONTROLS = {
    'ledger_metamorphic_consume_merged': ledger_metamorphic_consume_merged,
    'ledger_metamorphic_consume_split': ledger_metamorphic_consume_split,
    'ledger_metamorphic_restore_after_merged': ledger_metamorphic_restore_after_merged,
    'ledger_metamorphic_restore_after_split': ledger_metamorphic_restore_after_split,
    'ledger_metamorphic_restore_between_merged': ledger_metamorphic_restore_between_merged,
    'ledger_metamorphic_restore_between_split': ledger_metamorphic_restore_between_split,
    'ledger_metamorphic_restore_one_branch_merged': ledger_metamorphic_restore_one_branch_merged,
    'ledger_metamorphic_restore_one_branch_split': ledger_metamorphic_restore_one_branch_split,
}
