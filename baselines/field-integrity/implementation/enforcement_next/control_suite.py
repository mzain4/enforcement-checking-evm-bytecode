"""Authored controls for the three property rules.

Each control is a micro-program built from the same fact relations the decompiler emits. Expected outcomes
are stated per property; a control that distinguishes two semantically similar programs is the evidence that
a rule reads the intended dependency rather than a surface pattern. Controls are development/regression
tests, not scored CGT samples.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Tuple

from .controls import FactsBuilder


def _dispatcher(builder: FactsBuilder):
    builder.function('__function_selector__', '0x00000000')
    builder.block('0x1', [])
    builder.stmt('0x2', 'STOP')


def _call(builder, base=0x700, with_value=True, value=None, defines='0x19'):
    """A CALL with seven operands; `value` is a constant when given, otherwise SELFBALANCE."""
    gas = builder.stmt('0x%x' % (base + 0), 'CONST', defines=['0x%x' % (base + 0)], literal=0x8fc)
    to = builder.stmt('0x%x' % (base + 1), 'CALLER', defines=['0x%x' % (base + 1)])
    if value is None:
        value_var = builder.stmt('0x%x' % (base + 2), 'SELFBALANCE', defines=['0x%x' % (base + 2)])
    else:
        value_var = builder.stmt('0x%x' % (base + 2), 'CONST', defines=['0x%x' % (base + 2)], literal=value)
    offset = builder.stmt('0x%x' % (base + 3), 'CONST', defines=['0x%x' % (base + 3)], literal=0)
    size = builder.stmt('0x%x' % (base + 4), 'CONST', defines=['0x%x' % (base + 4)], literal=0)
    operands = [gas, to, value_var, offset, size, offset, size]
    if not with_value:
        operands = [gas, to, offset, size, offset, size]
        return builder.stmt('0x%x' % (base + 5), 'STATICCALL', uses=operands, defines=[defines])
    return builder.stmt('0x%x' % (base + 5), 'CALL', uses=operands, defines=[defines])


def control_104_ignored(directory: Path) -> Dict[str, object]:
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', [])
    _call(builder)
    builder.stmt('0x30', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'104': 'positive'}}


def control_104_rejected(directory: Path) -> Dict[str, object]:
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'])
    _call(builder)
    condition = builder.stmt('0x11', 'ISZERO', uses=['0x19'], defines=['0x11'])
    target = builder.stmt('0x12', 'CONST', defines=['0x12'], literal=0x30)
    builder.stmt('0x13', 'JUMPI', uses=[target, condition])
    builder.block('0x20', [])
    builder.stmt('0x21', 'STOP')
    builder.block('0x30', [])
    zero = builder.stmt('0x31', 'CONST', defines=['0x31'], literal=0)
    builder.stmt('0x32', 'REVERT', uses=[zero, zero])
    return {'facts': builder.emit(directory), 'expected': {'104': 'negative'}}


def control_104_inverted(directory: Path) -> Dict[str, object]:
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'])
    _call(builder)
    target = builder.stmt('0x12', 'CONST', defines=['0x12'], literal=0x30)
    builder.stmt('0x13', 'JUMPI', uses=[target, '0x19'])
    builder.block('0x20', [])
    builder.stmt('0x21', 'STOP')
    builder.block('0x30', [])
    zero = builder.stmt('0x31', 'CONST', defines=['0x31'], literal=0)
    builder.stmt('0x32', 'REVERT', uses=[zero, zero])
    return {'facts': builder.emit(directory), 'expected': {'104': 'positive'}}


def control_104_accepted(directory: Path) -> Dict[str, object]:
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'])
    _call(builder)
    condition = builder.stmt('0x11', 'ISZERO', uses=['0x19'], defines=['0x11'])
    target = builder.stmt('0x12', 'CONST', defines=['0x12'], literal=0x30)
    builder.stmt('0x13', 'JUMPI', uses=[target, condition])
    for block, prefix in (('0x20', '0x4'), ('0x30', '0x5')):
        builder.block(block, [])
        builder.stmt(prefix + '1', 'CONST', uses=[], defines=[prefix + '1'], literal=0)
        builder.stmt(prefix + '2', 'CONST', uses=[], defines=[prefix + '2'], literal=1)
        builder.stmt(prefix + '3', 'SSTORE', uses=[prefix + '1', prefix + '2'])
        builder.stmt(prefix + '4', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'104': 'positive'}}


def control_104_handled(directory: Path) -> Dict[str, object]:
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'])
    _call(builder)
    condition = builder.stmt('0x11', 'ISZERO', uses=['0x19'], defines=['0x11'])
    target = builder.stmt('0x12', 'CONST', defines=['0x12'], literal=0x30)
    builder.stmt('0x13', 'JUMPI', uses=[target, condition])
    builder.block('0x20', [])
    key = builder.stmt('0x41', 'CONST', defines=['0x41'], literal=0)
    value = builder.stmt('0x42', 'CONST', defines=['0x42'], literal=1)
    builder.stmt('0x43', 'SSTORE', uses=[key, value])
    builder.stmt('0x44', 'STOP')
    builder.block('0x30', [])
    key_failure = builder.stmt('0x51', 'CONST', defines=['0x51'], literal=7)
    value_failure = builder.stmt('0x52', 'CONST', defines=['0x52'], literal=1)
    builder.stmt('0x53', 'SSTORE', uses=[key_failure, value_failure])
    builder.stmt('0x54', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'104': 'negative'}}


def control_104_uncertain(directory: Path) -> Dict[str, object]:
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'])
    _call(builder)
    condition = builder.stmt('0x11', 'ISZERO', uses=['0x19'], defines=['0x11'])
    dynamic = builder.stmt('0x12', 'CALLDATALOAD', uses=[], defines=['0x12'])
    builder.stmt('0x13', 'JUMPI', uses=[dynamic, condition])
    builder.block('0x20', [])
    builder.stmt('0x21', 'STOP')
    builder.block('0x30', [])
    builder.stmt('0x31', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'104': 'unknown'}}


def control_104_mixed_continuations(directory: Path) -> Dict[str, object]:
    """The failure edge splits again: one continuation reverts, the other completes normally."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'])
    _call(builder)
    condition = builder.stmt('0x11', 'ISZERO', uses=['0x19'], defines=['0x11'])
    target = builder.stmt('0x12', 'CONST', defines=['0x12'], literal=0x30)
    builder.stmt('0x13', 'JUMPI', uses=[target, condition])
    builder.block('0x20', [])
    builder.stmt('0x21', 'STOP')
    builder.block('0x30', ['0x40', '0x50'])
    mode = builder.stmt('0x31', 'CALLDATALOAD', uses=[], defines=['0x31'])
    fail_target = builder.stmt('0x32', 'CONST', defines=['0x32'], literal=0x40)
    builder.stmt('0x33', 'JUMPI', uses=[fail_target, mode])
    builder.block('0x40', [])
    zero = builder.stmt('0x41', 'CONST', defines=['0x41'], literal=0)
    builder.stmt('0x42', 'REVERT', uses=[zero, zero])
    builder.block('0x50', [])
    builder.stmt('0x51', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'104': 'unknown'}}


def control_104_eq_two(directory: Path) -> Dict[str, object]:
    """A call result is 0 or 1, so `result == 2` never holds and the rejection branch is dead."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'])
    _call(builder)
    two = builder.stmt('0x11', 'CONST', defines=['0x11'], literal=2)
    condition = builder.stmt('0x12', 'EQ', uses=['0x19', two], defines=['0x12'])
    target = builder.stmt('0x13', 'CONST', defines=['0x13'], literal=0x30)
    builder.stmt('0x14', 'JUMPI', uses=[target, condition])
    builder.block('0x20', [])
    builder.stmt('0x21', 'STOP')
    builder.block('0x30', [])
    zero = builder.stmt('0x31', 'CONST', defines=['0x31'], literal=0)
    builder.stmt('0x32', 'REVERT', uses=[zero, zero])
    return {'facts': builder.emit(directory), 'expected': {'104': 'positive'}}


def control_104_eq_one(directory: Path) -> Dict[str, object]:
    """`result == 1` is exactly the success test, so rejecting on that branch does handle failure."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'])
    _call(builder)
    one = builder.stmt('0x11', 'CONST', defines=['0x11'], literal=1)
    condition = builder.stmt('0x12', 'EQ', uses=['0x19', one], defines=['0x12'])
    target = builder.stmt('0x13', 'CONST', defines=['0x13'], literal=0x30)
    builder.stmt('0x14', 'JUMPI', uses=[target, condition])
    builder.block('0x20', [])
    zero = builder.stmt('0x21', 'CONST', defines=['0x21'], literal=0)
    builder.stmt('0x22', 'REVERT', uses=[zero, zero])
    builder.block('0x30', [])
    builder.stmt('0x31', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'104': 'negative'}}


def _guarded_effect(builder, condition_var: str, *, authorized_true: bool, effect_op: str = 'SSTORE'):
    """Emit a two-way branch whose authorised edge reaches an effect and whose other edge reverts."""
    authorized_block, rejected_block = ('0x30', '0x20') if authorized_true else ('0x20', '0x30')
    builder.stmt('0x12', 'CONST', uses=[], defines=['0x12'],
                 literal=int(authorized_block, 16) if authorized_true else int(rejected_block, 16))
    builder.stmt('0x13', 'JUMPI', uses=['0x12', condition_var])
    for block, is_authorized in ((authorized_block, True), (rejected_block, False)):
        builder.block(block, [])
        if not is_authorized:
            zero = builder.stmt(block + '1', 'CONST', uses=[], defines=[block + '1'], literal=0)
            builder.stmt(block + '2', 'REVERT', uses=[zero, zero])
            continue
        if effect_op == 'SSTORE':
            key = builder.stmt(block + '1', 'CONST', uses=[], defines=[block + '1'], literal=1)
            value = builder.stmt(block + '2', 'CONST', uses=[], defines=[block + '2'], literal=1)
            builder.stmt(block + '3', 'SSTORE', uses=[key, value])
        builder.stmt(block + '4', 'STOP')


def control_115_origin_owner(directory: Path) -> Dict[str, object]:
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'])
    origin = builder.stmt('0x21', 'ORIGIN', uses=[], defines=['0x21'])
    slot = builder.stmt('0x22', 'CONST', uses=[], defines=['0x22'], literal=0)
    owner = builder.stmt('0x23', 'SLOAD', uses=[slot], defines=['0x23'])
    condition = builder.stmt('0x24', 'EQ', uses=[origin, owner], defines=['0x24'])
    _guarded_effect(builder, condition, authorized_true=True)
    return {'facts': builder.emit(directory), 'expected': {'115': 'positive'}}


def control_115_origin_caller(directory: Path) -> Dict[str, object]:
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'])
    origin = builder.stmt('0x21', 'ORIGIN', uses=[], defines=['0x21'])
    caller = builder.stmt('0x22', 'CALLER', uses=[], defines=['0x22'])
    condition = builder.stmt('0x24', 'EQ', uses=[origin, caller], defines=['0x24'])
    _guarded_effect(builder, condition, authorized_true=True)
    return {'facts': builder.emit(directory), 'expected': {'115': 'negative'}}


def control_115_log_only(directory: Path) -> Dict[str, object]:
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', [])
    origin = builder.stmt('0x21', 'ORIGIN', uses=[], defines=['0x21'])
    builder.stmt('0x22', 'LOG1', uses=['0x21', origin])
    builder.stmt('0x23', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'115': 'negative'}}


def control_105_unguarded(directory: Path) -> Dict[str, object]:
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', [])
    _call(builder)
    builder.stmt('0x30', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'positive'}}


def control_105_guarded(directory: Path) -> Dict[str, object]:
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'])
    caller = builder.stmt('0x21', 'CALLER', uses=[], defines=['0x21'])
    slot = builder.stmt('0x22', 'CONST', uses=[], defines=['0x22'], literal=0)
    owner = builder.stmt('0x23', 'SLOAD', uses=[slot], defines=['0x23'])
    condition = builder.stmt('0x24', 'EQ', uses=[caller, owner], defines=['0x24'])
    builder.stmt('0x25', 'CONST', uses=[], defines=['0x25'], literal=0x30)
    builder.stmt('0x26', 'JUMPI', uses=['0x25', condition])
    builder.block('0x20', [])
    zero = builder.stmt('0x27', 'CONST', uses=[], defines=['0x27'], literal=0)
    builder.stmt('0x28', 'REVERT', uses=[zero, zero])
    builder.block('0x30', [])
    _call(builder, base=0x800)
    builder.stmt('0x60', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'negative'}}


def control_105_guard_outside(directory: Path) -> Dict[str, object]:
    """The guard rejects one branch, but the transfer is reachable on both edges after the join."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'])
    caller = builder.stmt('0x21', 'CALLER', uses=[], defines=['0x21'])
    slot = builder.stmt('0x22', 'CONST', uses=[], defines=['0x22'], literal=0)
    owner = builder.stmt('0x23', 'SLOAD', uses=[slot], defines=['0x23'])
    condition = builder.stmt('0x24', 'EQ', uses=[caller, owner], defines=['0x24'])
    builder.stmt('0x25', 'CONST', uses=[], defines=['0x25'], literal=0x30)
    builder.stmt('0x26', 'JUMPI', uses=['0x25', condition])
    builder.block('0x20', ['0x40'])
    builder.stmt('0x27', 'CONST', uses=[], defines=['0x27'], literal=1)
    builder.stmt('0x28', 'SSTORE', uses=['0x27', '0x27'])
    builder.block('0x30', ['0x40'])
    builder.stmt('0x31', 'CONST', uses=[], defines=['0x31'], literal=0)
    builder.block('0x40', [])
    _call(builder, base=0x800)
    builder.stmt('0x60', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'positive'}}


def control_105_zero_value(directory: Path) -> Dict[str, object]:
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', [])
    _call(builder, base=0x900, value=0)
    builder.stmt('0x30', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'negative'}}


def control_105_self_bound(directory: Path) -> Dict[str, object]:
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', [])
    caller = builder.stmt('0x21', 'CALLER', uses=[], defines=['0x21'])
    balance = builder.stmt('0x22', 'SLOAD', uses=[caller], defines=['0x22'])
    gas = builder.stmt('0x23', 'CONST', defines=['0x23'], literal=0x8fc)
    offset = builder.stmt('0x24', 'CONST', defines=['0x24'], literal=0)
    builder.stmt('0x25', 'CALL', uses=[gas, caller, balance, offset, offset, offset, offset],
                 defines=['0x25'])
    zero = builder.stmt('0x26', 'CONST', defines=['0x26'], literal=0)
    builder.stmt('0x27', 'SSTORE', uses=[caller, zero])
    builder.stmt('0x28', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'negative'}}


def control_105_constant_payment(directory: Path) -> Dict[str, object]:
    """Pay a fixed amount to whoever calls: no guard, and a fixed amount is not the caller's own balance."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('claim', '0x11111111')
    builder.block('0x10', [])
    gas = builder.stmt('0x21', 'CONST', defines=['0x21'], literal=0x8fc)
    caller = builder.stmt('0x22', 'CALLER', uses=[], defines=['0x22'])
    amount = builder.stmt('0x23', 'CONST', defines=['0x23'], literal=1)
    offset = builder.stmt('0x24', 'CONST', defines=['0x24'], literal=0)
    builder.stmt('0x25', 'CALL', uses=[gas, caller, amount, offset, offset, offset, offset],
                 defines=['0x25'])
    builder.stmt('0x26', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'positive'}}


def control_105_inverted_limit(directory: Path) -> Dict[str, object]:
    """`require(amount >= balances[caller])`: the limit points the wrong way and lets the caller over-withdraw.

    Compiles to `JUMPI(ISZERO(LT(amount, balance)), revert, payment)`: the body runs only when the amount is at
    least the balance, so an over-withdrawal is exactly what passes.
    """
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'])
    caller = builder.stmt('0x21', 'CALLER', uses=[], defines=['0x21'])
    balance = builder.stmt('0x22', 'SLOAD', uses=[caller], defines=['0x22'])
    amount = builder.stmt('0x23', 'CALLDATALOAD', uses=[], defines=['0x23'])
    inner = builder.stmt('0x24', 'LT', uses=[amount, balance], defines=['0x24'])
    condition = builder.stmt('0x25', 'ISZERO', uses=[inner], defines=['0x25'])
    builder.stmt('0x26', 'CONST', uses=[], defines=['0x26'], literal=0x20)
    builder.stmt('0x27', 'JUMPI', uses=['0x26', condition])
    builder.block('0x20', [])
    zero = builder.stmt('0x28', 'CONST', uses=[], defines=['0x28'], literal=0)
    builder.stmt('0x29', 'REVERT', uses=[zero, zero])
    builder.block('0x30', [])
    _call(builder, base=0x800, value=None)
    builder.stmt('0x60', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'positive'}}


def control_105_forward_limit(directory: Path) -> Dict[str, object]:
    """`require(amount <= balances[caller])`: the limit rejects an over-withdrawal and protects the transfer.

    Compiles to `JUMPI(LT(balance, amount), revert, payment)`: the revert branch is taken on the
    over-withdrawal, and the transfer is reachable only from the other edge.
    """
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'])
    caller = builder.stmt('0x21', 'CALLER', uses=[], defines=['0x21'])
    balance = builder.stmt('0x22', 'SLOAD', uses=[caller], defines=['0x22'])
    amount = builder.stmt('0x23', 'CALLDATALOAD', uses=[], defines=['0x23'])
    condition = builder.stmt('0x24', 'LT', uses=[balance, amount], defines=['0x24'])
    builder.stmt('0x25', 'CONST', uses=[], defines=['0x25'], literal=0x20)
    builder.stmt('0x26', 'JUMPI', uses=['0x25', condition])
    builder.block('0x20', [])
    zero = builder.stmt('0x27', 'CONST', uses=[], defines=['0x27'], literal=0)
    builder.stmt('0x28', 'REVERT', uses=[zero, zero])
    builder.block('0x30', [])
    _call(builder, base=0x800, value=None)
    builder.stmt('0x60', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'negative'}}


def control_105_pays_when_overdrawn(directory: Path) -> Dict[str, object]:
    """`JUMPI(LT(balance, amount), payment, revert)`: the body pays exactly when the balance is too small."""
    builder = FactsBuilder()
    _dispatcher(builder)
    builder.function('withdraw', '0x11111111')
    builder.block('0x10', ['0x20', '0x30'])
    caller = builder.stmt('0x21', 'CALLER', uses=[], defines=['0x21'])
    balance = builder.stmt('0x22', 'SLOAD', uses=[caller], defines=['0x22'])
    amount = builder.stmt('0x23', 'CALLDATALOAD', uses=[], defines=['0x23'])
    condition = builder.stmt('0x24', 'LT', uses=[balance, amount], defines=['0x24'])
    builder.stmt('0x25', 'CONST', uses=[], defines=['0x25'], literal=0x30)
    builder.stmt('0x26', 'JUMPI', uses=['0x25', condition])
    builder.block('0x20', [])
    zero = builder.stmt('0x27', 'CONST', uses=[], defines=['0x27'], literal=0)
    builder.stmt('0x28', 'REVERT', uses=[zero, zero])
    builder.block('0x30', [])
    _call(builder, base=0x800, value=None)
    builder.stmt('0x60', 'STOP')
    return {'facts': builder.emit(directory), 'expected': {'105': 'positive'}}


CONTROLS = {
    '104_ignored': control_104_ignored,
    '104_rejected': control_104_rejected,
    '104_mixed_continuations': control_104_mixed_continuations,
    '104_eq_two': control_104_eq_two,
    '104_eq_one': control_104_eq_one,
    '105_constant_payment': control_105_constant_payment,
    '104_inverted': control_104_inverted,
    '104_accepted_failure': control_104_accepted,
    '104_handled_failure': control_104_handled,
    '104_uncertain_jump': control_104_uncertain,
    '115_origin_owner': control_115_origin_owner,
    '115_origin_caller': control_115_origin_caller,
    '115_log_only': control_115_log_only,
    '105_unguarded': control_105_unguarded,
    '105_guarded': control_105_guarded,
    '105_guard_outside': control_105_guard_outside,
    '105_zero_value': control_105_zero_value,
    '105_self_bound': control_105_self_bound,
    '105_forward_limit': control_105_forward_limit,
    '105_inverted_limit': control_105_inverted_limit,
    '105_pays_when_overdrawn': control_105_pays_when_overdrawn,
}


def build_all(root: Path) -> List[Tuple[str, Path, Dict[str, str]]]:
    rows = []
    for name, factory in CONTROLS.items():
        directory = Path(root) / name
        result = factory(directory)
        rows.append((name, result['facts'], result['expected']))
    return rows


