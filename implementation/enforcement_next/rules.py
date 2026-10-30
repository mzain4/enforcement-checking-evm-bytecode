"""Three property rules over the provenance and CFG layer.

Each rule returns a per-obligation result with evidence. Aggregation into one verdict per property is done in
`analyze.py`; the rules never see a label.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .tac import (
    ABNORMAL_TERMINAL_OPS,
    EFFECT_OPS,
    EXTERNAL_CALL_OPS,
    TERMINAL_OPS,
    VALUE_CALL_INDEX,
    Condition,
    FunctionView,
    Guard,
    Provenance,
    analyze_condition,
    block_of_instruction,
    expression_signature,
    instruction_defining,
    provenance_map,
    resolve_constant,
    same_storage_slot,
    storage_read_key,
)


@dataclass
class Obligation:
    property: str
    status: str                      # positive | negative | unknown
    reason: str
    evidence: Dict[str, object] = field(default_factory=dict)


def branch_conditions(facts, view: FunctionView,
                      values: Dict[str, Provenance]) -> List[Tuple[str, str, Condition]]:
    """Every JUMPI in the function as (block id, condition variable, decomposed condition)."""
    rows: List[Tuple[str, str, Condition]] = []
    for block_id in sorted(view.blocks):
        instructions = view.instructions(block_id)
        if not instructions:
            continue
        last = instructions[-1]
        if last.op != 'JUMPI' or len(last.uses) < 2:
            continue
        rows.append((block_id, last.uses[1], analyze_condition(facts, values, last.uses[1])))
    return rows


def guards_of(facts, view: FunctionView, values: Dict[str, Provenance]) -> List[Guard]:
    guards: List[Guard] = []
    for block_id, _, condition in branch_conditions(facts, view, values):
        if condition.authorized_true is None:
            continue
        guards.append(Guard(block=block_id, condition=condition,
                            authorized_true=bool(condition.authorized_true)))
    return guards


def edge_targets(view: FunctionView, block_id: str) -> Dict[bool, str]:
    targets: Dict[bool, str] = {}
    for successor, polarity in view.successors.get(block_id, []):
        if polarity is None:
            continue
        targets[polarity] = successor
    return targets


# --------------------------------------------------------------------------------------------------------
# SWC-104: unchecked call return value
# --------------------------------------------------------------------------------------------------------

def _dependents(facts, view: FunctionView, seed: str) -> Tuple[Set[str], bool]:
    """Transitive dependents of a value inside one function; also reports a private return of the value."""
    dependents: Set[str] = set()
    frontier = {seed}
    returned = False
    while frontier:
        current = frontier.pop()
        for block_id in view.blocks:
            for instruction in view.instructions(block_id):
                if current not in instruction.uses:
                    continue
                if instruction.op == 'RETURNPRIVATE':
                    returned = True
                for defined in instruction.defines:
                    if defined not in dependents:
                        dependents.add(defined)
                        frontier.add(defined)
    return dependents, returned


def _bool_form(facts, variable: str, seed: str, depth: int = 0):
    """Reduce an expression to a form over the call result.

    `('seed', inverted)` means the expression is true exactly when the call result is non-zero (`inverted`
    false) or exactly when it is zero (`inverted` true). `('const', value)` is a folded constant; the value is
    kept rather than its truthiness so that a comparison with a non-binary constant is not mistaken for a
    test of the success bit.
    """
    if depth > 10:
        return None
    if variable == seed:
        return ('seed', False)
    instruction = instruction_defining(facts, variable)
    if instruction is None:
        return None
    op = instruction.op
    if op == 'CONST':
        value = resolve_constant(facts, variable)
        return None if value is None else ('const', value)
    if op == 'ISZERO' and instruction.uses:
        inner = _bool_form(facts, instruction.uses[0], seed, depth + 1)
        return None if inner is None else _negate(inner)
    if op in {'EQ', 'NE'} and len(instruction.uses) >= 2:
        left = _bool_form(facts, instruction.uses[0], seed, depth + 1)
        right = _bool_form(facts, instruction.uses[1], seed, depth + 1)
        if left is None or right is None:
            return None
        equal = _equal_form(left, right)
        return equal if op == 'EQ' else _negate(equal)
    if op in {'AND', 'OR'} and len(instruction.uses) >= 2:
        left = _bool_form(facts, instruction.uses[0], seed, depth + 1)
        right = _bool_form(facts, instruction.uses[1], seed, depth + 1)
        if left is None or right is None:
            return None
        return _and_form(left, right) if op == 'AND' else _or_form(left, right)
    if op == 'PHI' and seed in instruction.uses:
        others = [use for use in instruction.uses if use != seed]
        if not others or all(resolve_constant(facts, other) == 0 for other in others):
            return ('seed', False)
    return None


def _negate(form):
    kind, value = form
    return ('const', 0 if value else 1) if kind == 'const' else ('seed', not value)


def _equal_form(left, right):
    """Equality of two forms. A call result is 0 or 1, so `result == k` is constantly false for k > 1."""
    (lk, lv), (rk, rv) = left, right
    if lk == 'const' and rk == 'const':
        return ('const', 1 if lv == rv else 0)
    if lk == 'seed' and rk == 'seed':
        return ('const', 1 if lv == rv else 0)
    seed_inverted, constant = (lv, rv) if lk == 'seed' else (rv, lv)
    if constant not in (0, 1):
        return ('const', 0)
    return ('seed', (0 if constant else 1) ^ seed_inverted)


def _and_form(left, right):
    (lk, lv), (rk, rv) = left, right
    if lk == 'const' and rk == 'const':
        return ('const', 1 if (lv and rv) else 0)
    if lk == 'const':
        return right if lv else ('const', 0)
    if rk == 'const':
        return left if rv else ('const', 0)
    return ('seed', lv) if lv == rv else ('const', 0)


def _or_form(left, right):
    (lk, lv), (rk, rv) = left, right
    if lk == 'const' and rk == 'const':
        return ('const', 1 if (lv or rv) else 0)
    if lk == 'const':
        return ('const', 1) if lv else right
    if rk == 'const':
        return ('const', 1) if rv else left
    return ('seed', lv) if lv == rv else ('const', 1)


def _zero_polarity(facts, values: Dict[str, Provenance], variable: str, seed: str,
                   depth: int = 0) -> Optional[bool]:
    """True when the condition variable is true exactly when the call result is zero."""
    form = _bool_form(facts, variable, seed)
    if form is None or form[0] != 'seed':
        return None
    return bool(form[1])


def _effects_and_terminals(facts, view: FunctionView, start: str,
                           allowed: Optional[Set[str]] = None) -> Tuple[List[tuple], List[str], bool]:
    """Collect effect signatures and terminal kinds reachable from a block.

    When `allowed` is given, traversal stays inside that block set (a branch-exclusive region) and a path that
    leaves the region is simply a join with the other branch. The third value is True when the traversal met
    an unsupported edge (a fragment we cannot follow).
    """
    effects: List[tuple] = []
    terminals: List[str] = []
    unknown = False
    seen: Set[str] = set()
    stack = [start] if start in view.blocks else []
    while stack:
        block_id = stack.pop()
        if block_id in seen:
            continue
        if allowed is not None and block_id not in allowed:
            continue
        seen.add(block_id)
        for instruction in view.instructions(block_id):
            if instruction.op in ABNORMAL_TERMINAL_OPS:
                terminals.append('abnormal')
                break
            if instruction.op == 'STOP' or instruction.op == 'RETURN' or instruction.op == 'RETURNPRIVATE':
                terminals.append('normal')
                break
            if instruction.op in EFFECT_OPS:
                effects.append(_effect_signature(facts, instruction))
        else:
            edges = view.successors.get(block_id, [])
            if not edges:
                terminals.append('end')
            instructions = view.instructions(block_id)
            last = instructions[-1] if instructions else None
            ambiguous = bool(last) and (last.op == 'JUMPI' or (last.op == 'JUMP' and len(edges) > 1))
            for successor, polarity in edges:
                if successor not in view.blocks:
                    unknown = True
                    continue
                if allowed is not None and successor not in allowed:
                    continue
                if polarity is None and ambiguous:
                    unknown = True
                stack.append(successor)
    return effects, terminals, unknown


def instruction_is_branch(view: FunctionView, block_id: str) -> bool:
    instructions = view.instructions(block_id)
    return bool(instructions) and instructions[-1].op in {'JUMPI', 'JUMP'}


def _effect_signature(facts, instruction) -> tuple:
    op = instruction.op
    if op == 'SSTORE' and instruction.uses:
        key = resolve_constant(facts, instruction.uses[0])
        return ('SSTORE', key if key is not None else instruction.uses[0])
    if op in {'CALL', 'CALLCODE'} and len(instruction.uses) >= 3:
        return (op, instruction.uses[1], instruction.uses[2])
    if op in {'DELEGATECALL', 'STATICCALL'} and len(instruction.uses) >= 2:
        return (op, instruction.uses[1])
    if op.startswith('LOG'):
        return ('LOG', op)
    return (op,)


def call_result_obligations(facts, view: FunctionView, flags: Dict[str, bool]) -> List[Obligation]:
    values = provenance_map(facts, view)
    obligations: List[Obligation] = []
    for block_id in sorted(view.blocks):
        for instruction in view.instructions(block_id):
            if instruction.op not in EXTERNAL_CALL_OPS:
                continue
            if not instruction.defines:
                obligations.append(Obligation('104', 'unknown',
                                              'external call without a result variable',
                                              {'instruction': instruction.id, 'function': view.name}))
                continue
            success = instruction.defines[0]
            dependents, returned = _dependents(facts, view, success)
            used = bool(dependents) or _any_use(facts, success)
            evidence = {'function': view.name, 'call_block': block_id, 'instruction': instruction.id,
                        'success_value': success, 'call_op': instruction.op}
            if not flags['callresult_dependency']:
                status = 'positive' if not used else 'negative'
                obligations.append(Obligation(
                    '104', status,
                    'presence rule: ' + ('result never read' if not used else 'result is read'),
                    evidence))
                continue
            if not used:
                obligations.append(Obligation('104', 'positive', 'result never read', evidence))
                continue
            branch_guards = [Guard(block=block_id, condition=condition, authorized_true=bool(condition.authorized_true))
                             for block_id, _, condition in branch_conditions(facts, view, values)
                             if _depends_on(facts, guard_block_condition(facts, view, block_id), success)]
            if not branch_guards:
                if returned:
                    obligations.append(Obligation(
                        '104', 'unknown', 'result is returned to the caller; the decision is not local', evidence))
                else:
                    obligations.append(Obligation(
                        '104', 'positive', 'result is read but no branch depends on it', evidence))
                continue
            verdicts = []
            for guard in branch_guards:
                verdicts.append(_judge_guard(facts, view, values, guard, success, evidence))
            if any(v.status == 'positive' for v in verdicts):
                obligations.extend(v for v in verdicts if v.status == 'positive')
            elif any(v.status == 'unknown' for v in verdicts):
                obligations.extend(v for v in verdicts if v.status == 'unknown')
            else:
                obligations.extend(verdicts)
    return obligations


def guard_block_condition(facts, view: FunctionView, block_id: str) -> str:
    instructions = view.instructions(block_id)
    return instructions[-1].uses[1]


def _any_use(facts, variable: str) -> bool:
    return any(variable in instruction.uses for instruction in facts.instructions.values())


def _depends_on(facts, condition_variable: str, seed: str) -> bool:
    frontier = {condition_variable}
    seen: Set[str] = set()
    while frontier:
        current = frontier.pop()
        if current in seen:
            continue
        seen.add(current)
        if current == seed:
            return True
        instruction = instruction_defining(facts, current)
        if instruction is None:
            continue
        frontier.update(instruction.uses)
    return False


def _judge_guard(facts, view: FunctionView, values: Dict[str, Provenance], guard: Guard,
                 success: str, evidence: Dict[str, object]) -> Obligation:
    form = _bool_form(facts, guard_block_condition(facts, view, guard.block), success)
    if form is None:
        return Obligation('104', 'unknown', 'call-result branch cannot be reduced to a zero test',
                          dict(evidence, guard_block=guard.block))
    if form[0] == 'const':
        return Obligation('104', 'positive',
                          'the branch condition on the call result is constant, so it never tests failure',
                          dict(evidence, guard_block=guard.block, verdict='constant-condition',
                               condition_value=form[1]))
    zero_true = bool(form[1])
    failure_polarity = zero_true
    targets = edge_targets(view, guard.block)
    failure_target = targets.get(failure_polarity)
    success_target = targets.get(not failure_polarity)
    if failure_target is None:
        return Obligation('104', 'unknown', 'failure edge cannot be resolved',
                          dict(evidence, guard_block=guard.block))
    if success_target is None:
        return Obligation('104', 'unknown', 'success edge cannot be resolved',
                          dict(evidence, guard_block=guard.block))
    success_reach = view.reachable([success_target])
    failure_reach = view.reachable([failure_target])
    failure_only = failure_reach - success_reach
    success_only = success_reach - failure_reach
    if not failure_only:
        if failure_target in success_reach:
            return Obligation('104', 'unknown',
                              'the successful path can reach the failure continuation through a cycle; '
                              'effects cannot be attributed without path conditions',
                              dict(evidence, guard_block=guard.block, verdict='cyclic'))
        inverted = False
        if success_only:
            success_effects, success_terminals, _ = _effects_and_terminals(
                facts, view, success_target, allowed=success_only)
            inverted = 'abnormal' in success_terminals and not success_effects
        return Obligation('104', 'positive',
                          'the branch rejects the successful outcome instead of the failure' if inverted
                          else 'failure rejoins the successful path with no handling',
                          dict(evidence, guard_block=guard.block,
                               verdict='inverted' if inverted else 'accepted'))
    fail_effects, fail_terminals, fail_unknown = _effects_and_terminals(
        facts, view, failure_target, allowed=failure_only)
    rejecting = [terminal for terminal in fail_terminals if terminal == 'abnormal']
    completing = [terminal for terminal in fail_terminals if terminal in {'normal', 'end'}]
    if fail_unknown:
        return Obligation('104', 'unknown', 'failure path leaves the supported fragment',
                          dict(evidence, guard_block=guard.block))
    if rejecting and completing:
        return Obligation('104', 'unknown',
                          'the failure branch has both rejecting and continuing continuations',
                          dict(evidence, guard_block=guard.block, verdict='mixed'))
    if rejecting:
        return Obligation('104', 'negative', 'failure outcome is rejected on its own path',
                          dict(evidence, guard_block=guard.block, verdict='rejected'))
    if not fail_effects:
        return Obligation('104', 'positive', 'failure takes a differentiated path with no effect of its own',
                          dict(evidence, guard_block=guard.block, verdict='accepted'))
    success_effects, _, success_unknown = _effects_and_terminals(
        facts, view, success_target, allowed=success_only)
    if success_unknown:
        return Obligation('104', 'unknown', 'success path leaves the supported fragment',
                          dict(evidence, guard_block=guard.block))
    if set(fail_effects) <= set(success_effects):
        return Obligation('104', 'positive',
                          'failure continues to the same effects as success',
                          dict(evidence, guard_block=guard.block, verdict='accepted',
                               failure_effects=sorted(map(str, set(fail_effects))),
                               success_effects=sorted(map(str, set(success_effects)))))
    return Obligation('104', 'negative', 'failure takes a different branch with its own effects',
                      dict(evidence, guard_block=guard.block, verdict='handled',
                           failure_effects=sorted(map(str, set(fail_effects))),
                           success_effects=sorted(map(str, set(success_effects)))))


# --------------------------------------------------------------------------------------------------------
# SWC-115: authorisation through tx.origin
# --------------------------------------------------------------------------------------------------------

def origin_obligations(facts, view: FunctionView, flags: Dict[str, bool]) -> List[Obligation]:
    values = provenance_map(facts, view)
    origins = [(block_id, instruction.id) for block_id in sorted(view.blocks)
               for instruction in view.instructions(block_id) if instruction.op == 'ORIGIN']
    if not origins:
        return [Obligation('115', 'negative', 'no ORIGIN in the analysed function',
                           {'function': view.name})]
    if not flags['origin_role']:
        return [Obligation('115', 'positive', 'ORIGIN appears in public-reachable code',
                           {'function': view.name, 'origins': origins})]
    obligations: List[Obligation] = []
    saw_uncertain = False
    for guard in guards_of(facts, view, values):
        condition = guard.condition
        if not condition.origin:
            continue
        targets = edge_targets(view, guard.block)
        authorized_target = targets.get(guard.authorized_true)
        unauthorized_target = targets.get(not guard.authorized_true)
        if authorized_target is None or unauthorized_target is None:
            saw_uncertain = True
            continue
        if condition.caller_vs_origin:
            obligations.append(Obligation(
                '115', 'negative', 'origin is only compared with the caller',
                {'function': view.name, 'guard_block': guard.block, 'condition': condition.description}))
            continue
        if condition.identity and condition.identity_kind in {'storage', 'const'}:
            authorized = _effect_signatures(facts, view, authorized_target)
            unauthorized = _effect_signatures(facts, view, unauthorized_target)
            gated = [effect for effect in authorized if effect not in unauthorized]
            if gated:
                obligations.append(Obligation(
                    '115', 'positive', 'origin identity check gates an effect',
                    {'function': view.name, 'guard_block': guard.block,
                     'condition': condition.description, 'gated_effects': sorted(map(str, gated))}))
            else:
                obligations.append(Obligation(
                    '115', 'negative', 'origin identity check does not gate an effect',
                    {'function': view.name, 'guard_block': guard.block}))
            continue
        saw_uncertain = True
    if any(obligation.status == 'positive' for obligation in obligations):
        return [obligation for obligation in obligations if obligation.status == 'positive']
    if saw_uncertain:
        return [Obligation('115', 'unknown',
                           'origin influences a branch whose identity operand is not established',
                           {'function': view.name, 'origins': origins})]
    if obligations:
        return obligations
    return [Obligation('115', 'negative', 'origin is not used in a branch that gates an effect',
                       {'function': view.name, 'origins': origins})]


def _effect_signatures(facts, view: FunctionView, start: str) -> List[tuple]:
    effects: List[tuple] = []
    for block_id in view.reachable([start]):
        for instruction in view.instructions(block_id):
            if instruction.op in EFFECT_OPS or instruction.op == 'CALLPRIVATE':
                effects.append(_effect_signature(facts, instruction))
    return effects


# --------------------------------------------------------------------------------------------------------
# SWC-105: unprotected Ether withdrawal
# --------------------------------------------------------------------------------------------------------

def ether_transfer_obligations(facts, view: FunctionView, flags: Dict[str, bool],
                               inherited_guards: List[Guard]) -> List[Obligation]:
    values = provenance_map(facts, view)
    guards = guards_of(facts, view, values)
    obligations: List[Obligation] = []
    for block_id in sorted(view.blocks):
        for instruction in view.instructions(block_id):
            if instruction.op not in VALUE_CALL_INDEX:
                continue
            index = VALUE_CALL_INDEX[instruction.op]
            if len(instruction.uses) <= index:
                continue
            value = resolve_constant(facts, instruction.uses[index])
            if value == 0:
                continue
            evidence = {'function': view.name, 'call_block': block_id, 'instruction': instruction.id,
                        'value_operand_constant': value}
            consumption, residue = ('not-consumed', {})
            if flags['guard_dominance']:
                consumption, residue = _caller_bound(facts, view, values, instruction)
            if consumption == 'consumed':
                obligations.append(Obligation(
                    '105', 'negative',
                    'recipient is the caller and the transferred amount is a caller-keyed balance that is '
                    'debited on every path completing the payment', dict(evidence, **residue)))
                continue
            if not flags['guard_dominance']:
                protected = bool(guards) or bool(inherited_guards) or _has_caller_condition(facts, view, values)
                obligations.append(Obligation(
                    '105', 'negative' if protected else 'positive',
                    'presence rule: ' + ('a caller comparison exists' if protected else 'no caller comparison'),
                    evidence))
                continue
            protection = _protection(facts, view, guards, inherited_guards, block_id)
            if protection == 'protected':
                obligations.append(Obligation('105', 'negative', 'an identity or limit guard dominates the transfer',
                                              dict(evidence, guard=protection.detail)))  # type: ignore[union-attr]
            elif protection == 'unprotected':
                if consumption == 'unknown':
                    obligations.append(Obligation(
                        '105', 'unknown',
                        'no caller guard dominates the transfer and ledger consumption cannot be decided',
                        dict(evidence, **residue)))
                else:
                    obligations.append(Obligation('105', 'positive', 'no caller guard dominates the transfer',
                                                  dict(evidence, **residue)))
            else:
                obligations.append(Obligation('105', 'unknown', 'guard analysis is inconclusive',
                                              evidence))
    return obligations


class Protection(str):
    """String subclass carrying the deciding guard for evidence."""

    def __new__(cls, value: str, detail: str = ''):
        instance = super().__new__(cls, value)
        instance.detail = detail
        return instance


def _caller_bound(facts, view: FunctionView, values: Dict[str, Provenance],
                  instruction) -> Tuple[str, Dict[str, object]]:
    """Decide whether the transfer is a caller-keyed withdrawal whose ledger entry is really consumed.

    Returns `consumed`, `not-consumed` or `unknown`. A fixed amount is not the caller's own balance, so a
    constant amount is always `not-consumed`. Beyond that, two things must be shown and each is reported
    separately: the amount is a read of a caller-keyed slot, and that same slot is debited on *every* path that
    completes the payment successfully, by an amount that covers what was paid. When either cannot be
    established the answer is `unknown`, never `consumed`.
    """
    if len(instruction.uses) < 3:
        return 'not-consumed', {}
    recipient = values.get(instruction.uses[1], Provenance())
    amount = values.get(instruction.uses[2], Provenance())
    if not recipient.caller or recipient.origin:
        return 'not-consumed', {}
    if amount.const_known:
        return 'not-consumed', {'caller_bound': 'fixed amount is not a caller-keyed balance'}
    read_key = storage_read_key(facts, instruction.uses[2])
    if read_key is None or not values.get(read_key, Provenance()).caller:
        return 'not-consumed', {'caller_bound': 'the amount is not a read of a caller-keyed slot'}
    block_id = block_of_instruction(facts, view, instruction.id)
    residue = _ledger_consumption(facts, view, block_id, instruction.uses[2], read_key)
    return str(residue['outcome']), residue


def _is_success_terminal(view: FunctionView, block_id: str) -> bool:
    instructions = view.instructions(block_id)
    if not instructions:
        return True
    last = instructions[-1]
    if last.op in ABNORMAL_TERMINAL_OPS:
        return False
    if last.op in {'STOP', 'RETURN', 'RETURNPRIVATE'}:
        return True
    return not view.successors.get(block_id)


def _reachable_avoiding(view: FunctionView, start: str, avoid: Optional[str],
                        allowed: Optional[Set[str]] = None) -> Set[str]:
    """Blocks reachable from `start`, optionally inside `allowed` and without passing through `avoid`."""
    seen: Set[str] = set()
    stack = [start] if start in view.blocks else []
    while stack:
        block_id = stack.pop()
        if block_id in seen or block_id == avoid:
            continue
        if allowed is not None and block_id not in allowed:
            continue
        seen.add(block_id)
        for successor, _ in view.successors.get(block_id, []):
            if successor in view.blocks and successor not in seen and successor != avoid:
                stack.append(successor)
    return seen


def _success_region(view: FunctionView, transfer_block: Optional[str]) -> Optional[Set[str]]:
    """Blocks that lie on some path from the transfer to a successful completion, or None when unknown."""
    if transfer_block is None:
        return None
    forward = _reachable_avoiding(view, transfer_block, None)
    terminals = {block_id for block_id in forward if _is_success_terminal(view, block_id)}
    if not terminals:
        return set()
    backward: Set[str] = set()
    for block_id in sorted(forward):
        if block_id in terminals or terminals & _reachable_avoiding(view, block_id, None):
            backward.add(block_id)
    return backward


def _dominates_completion(view: FunctionView, transfer_block: str, debit_block: str,
                          region: Set[str]) -> bool:
    """Every path from the transfer to a successful completion passes through `debit_block`."""
    terminals = {block_id for block_id in region if _is_success_terminal(view, block_id)}
    if not terminals:
        return False
    without = _reachable_avoiding(view, transfer_block, debit_block, region)
    return not (terminals & without)


def _dominates_block(view: FunctionView, dominator: str, block_id: str) -> bool:
    """Every path from the function entry to `block_id` passes through `dominator`."""
    return block_id not in _reachable_avoiding(view, view.entry, dominator)


def _statement_order(view: FunctionView) -> Dict[str, Dict[str, int]]:
    """Position of each statement inside its block, so that same-block ordering is comparable."""
    order: Dict[str, Dict[str, int]] = {}
    for block_id in view.blocks:
        order[block_id] = {instruction.id: index
                           for index, instruction in enumerate(view.instructions(block_id))}
    return order


def _can_reach(view: FunctionView, start: str, target: str) -> bool:
    return target in _reachable_avoiding(view, start, None)


def _restored_after(view: FunctionView, debit: Dict[str, object], restorations: List[Dict[str, object]],
                    region: Set[str], order: Dict[str, Dict[str, int]], transfer_block: str) -> bool:
    """True when a same-slot non-debit write can undo the debit before the payment or after it.

    The traversal starts at the block holding the debit and is not restricted to the post-payment region: a
    restoration may sit in a block between the debit and the payment (which the region, being forward from the
    transfer, does not contain) or after the payment on a completing path. A block qualifies when it is a
    successor of the debit that can still reach the transfer, or when it lies in the region that completes.
    Inside the debit's own block, statement order decides.
    """
    debit_block = str(debit['block'])
    debit_position = order.get(debit_block, {}).get(str(debit['write']), -1)
    reachable_from_debit = _reachable_avoiding(view, debit_block, None)
    reachable_from_debit.add(debit_block)
    before_payment = {block_id for block_id in reachable_from_debit
                      if block_id != transfer_block and _can_reach(view, block_id, transfer_block)}
    for restore in restorations:
        block_id = str(restore['block'])
        if block_id == debit_block:
            if order.get(block_id, {}).get(str(restore['write']), -1) > debit_position:
                return True
            continue
        if block_id == transfer_block or block_id in before_payment or block_id in region:
            return True
    return False


def _ledger_consumption(facts, view: FunctionView, transfer_block: Optional[str],
                        amount_variable: str, read_key: str) -> Dict[str, object]:
    """Whether the caller-keyed slot the amount was read from is debited on every successful payment path.

    A write counts only when it addresses the same slot *and* debits an amount that covers what was paid --- a
    zero fill of that slot, or a subtraction of exactly the paid amount. Any other same-slot write (unchanged
    value, credit, partial debit) is a restoration candidate: if one can follow the debit on a path that
    completes, the ledger is not consumed.
    """
    key_signature = expression_signature(facts, view, read_key)
    residue: Dict[str, object] = {
        'outcome': 'not-consumed', 'read_slot': read_key,
        'slot_identity': 'signature' if key_signature is not None else 'variable',
        'writes_examined': 0, 'debits': [], 'restorations': []}
    if key_signature is None:
        residue['outcome'] = 'unknown'
        residue['reason'] = 'the identity of the slot the amount was read from cannot be established'
        return residue
    debits: List[Dict[str, object]] = []
    restorations: List[Dict[str, object]] = []
    for block_id in sorted(view.blocks):
        for instruction in view.instructions(block_id):
            if instruction.op != 'SSTORE' or len(instruction.uses) < 2:
                continue
            written_key = instruction.uses[0]
            if not same_storage_slot(facts, view, read_key, written_key, key_signature):
                continue
            residue['writes_examined'] = int(residue['writes_examined']) + 1
            kind = _debit_kind(facts, view, instruction.uses[1], read_key, key_signature, amount_variable)
            record = {'write': instruction.id, 'block': block_id,
                      'written': instruction.uses[1], 'kind': kind or 'not-a-debit'}
            (debits if kind else restorations).append(record)
    residue['debits'] = debits
    residue['restorations'] = restorations
    if not residue['writes_examined']:
        residue['reason'] = 'no write to the slot the amount was read from'
        return residue
    if view.partial:
        residue['outcome'] = 'unknown'
        residue['reason'] = ('the function has an unresolved jump, so no property of all paths can be '
                            'established')
        return residue
    region = _success_region(view, transfer_block)
    if not region:
        residue['reason'] = 'no successful completion is reachable from the transfer'
        return residue
    order = _statement_order(view)
    for record in debits:
        block_id = str(record['block'])
        if block_id not in region:
            continue
        if not _dominates_completion(view, str(transfer_block), block_id, region):
            continue
        if _restored_after(view, record, restorations, region, order, str(transfer_block)):
            continue
        residue['outcome'] = 'consumed'
        residue['debit'] = record['kind']
        residue['debit_write'] = record['write']
        residue['debit_block'] = block_id
        return residue
    for record in debits:
        block_id = str(record['block'])
        if not _dominates_block(view, block_id, str(transfer_block)):
            continue
        if _restored_after(view, record, restorations, region, order, str(transfer_block)):
            continue
        residue['outcome'] = 'consumed'
        residue['debit'] = record['kind']
        residue['debit_write'] = record['write']
        residue['debit_block'] = block_id
        residue['debit_position'] = 'before the transfer'
        return residue

    if debits:
        if any(not _dominates_completion(view, str(transfer_block), str(record['block']), region)
               for record in debits):
            residue['reason'] = 'a debit exists but does not cover every path that completes the payment'
        elif restorations:
            residue['reason'] = 'a later write to the same slot restores the ledger'
        else:
            residue['reason'] = 'the debit is not ordered before or after the payment on every path'
    else:
        residue['reason'] = 'the same-slot write is not a debit of the paid amount'
    return residue


def _debit_kind(facts, view: FunctionView, written: str, read_key: str,
                key_signature: Optional[tuple], amount_variable: str) -> Optional[str]:
    """Classify a same-slot write as a debit that covers the paid amount, or reject it.

    Clearing the slot covers the balance the amount was read from. A subtraction covers the amount only when
    the subtrahend *is* that amount: depending on it is not enough, because `amount - amount` depends on the
    amount and subtracts nothing.
    """
    if resolve_constant(facts, written) == 0:
        return 'cleared'
    instruction = instruction_defining(facts, written)
    if instruction is None or instruction.op != 'SUB' or len(instruction.uses) < 2:
        return None
    previous, debit = instruction.uses[0], instruction.uses[1]
    previous_key = storage_read_key(facts, previous)
    if previous_key is None or not same_storage_slot(facts, view, read_key, previous_key, key_signature):
        return None
    if not _same_amount(facts, view, debit, amount_variable):
        return None
    return 'debited'


def _same_amount(facts, view: FunctionView, subtrahend: str, amount_variable: str) -> bool:
    """True only when the subtracted value provably is the paid amount rather than merely derived from it."""
    if subtrahend == amount_variable:
        return True
    if resolve_constant(facts, subtrahend) is not None:
        return False                     # the paid amount is a storage read, so it is not a constant
    left = expression_signature(facts, view, subtrahend)
    right = expression_signature(facts, view, amount_variable)
    return left is not None and left == right


def _on_common_path(view: FunctionView, sstore_block: str, transfer_block: Optional[str]) -> bool:
    if transfer_block is None:
        return False
    if sstore_block == transfer_block:
        return True
    if view.reachable_from_block(sstore_block, transfer_block):
        return True
    return view.reachable_from_block(transfer_block, sstore_block)


def _has_caller_condition(facts, view: FunctionView, values: Dict[str, Provenance]) -> bool:
    for block_id in view.blocks:
        instructions = view.instructions(block_id)
        if not instructions or instructions[-1].op != 'JUMPI' or len(instructions[-1].uses) < 2:
            continue
        condition = analyze_condition(facts, values, instructions[-1].uses[1])
        if condition.caller and (condition.identity or condition.limit or condition.caller_vs_origin):
            return True
    return False


def _protection(facts, view: FunctionView, guards: List[Guard], inherited: List[Guard],
                block_id: str) -> Protection:
    """Decide whether a dominating guard protects *this* transfer.

    The test is stated in terms of the transfer rather than of edge positions: a guard protects when the
    predicate has an authorised value, the transfer is reachable from that edge and from no other, and the
    other edge's exclusive region rejects without an effect. Because the authorised value comes from the
    predicate's meaning (`amount <= balance` in any of its compilations), two equivalent guards written with
    different operators, a different negation or swapped branch targets reach the same verdict.
    """
    candidates = [guard for guard in guards if guard.block in view.dominators.get(block_id, set())]
    candidates.extend(inherited)
    inconclusive = False
    for guard in candidates:
        condition = guard.condition
        if not (condition.identity or condition.limit):
            continue
        if condition.limit and condition.limit_inverted:
            continue                      # the bound admits an over-withdrawal: no protection
        authorized = guard.authorized_true if condition.authorized_true is not None else None
        if authorized is None:
            inconclusive = True
            continue
        if guard in inherited:
            return Protection('protected', '%s at caller site %s' % (condition.description, guard.block))
        targets = edge_targets(view, guard.block)
        authorized_target = targets.get(authorized)
        rejected_target = targets.get(not authorized)
        if authorized_target is None or rejected_target is None:
            inconclusive = True
            continue
        if not view.reachable_from_block(authorized_target, block_id):
            continue                      # the transfer is not on the authorised edge, so the guard is moot
        if view.reachable_from_block(rejected_target, block_id):
            continue                      # the transfer survives the rejected edge: no protection
        rejected_region = view.reachable([rejected_target]) - view.reachable([authorized_target])
        if not rejected_region:
            inconclusive = True
            continue
        effects, terminals, unknown = _effects_and_terminals(
            facts, view, rejected_target, allowed=rejected_region)
        if unknown or not terminals:
            inconclusive = True
            continue
        if effects:
            continue                      # the rejected edge has effects of its own before it stops
        if all(terminal == 'abnormal' for terminal in terminals):
            return Protection('protected', '%s at %s (the other edge rejects)'
                              % (condition.description, guard.block))
    return Protection('unknown', 'a caller comparison exists but does not decide the transfer') \
        if inconclusive else Protection('unprotected')
