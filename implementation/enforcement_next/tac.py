"""CFG, constant and provenance helpers for the next-generation enforcement rules.

The analyser consumes only a Gigahorse fact tree through the inherited `Facts` loader. It never reads a
label, a contract name, a provider category or an expected result.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

EXTERNAL_CALL_OPS = {'CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL'}
TERMINAL_OPS = {'STOP', 'RETURN', 'REVERT', 'INVALID', 'SELFDESTRUCT', 'THROW'}
ABNORMAL_TERMINAL_OPS = {'REVERT', 'INVALID', 'THROW'}
EFFECT_OPS = {'SSTORE', 'CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL',
              'LOG0', 'LOG1', 'LOG2', 'LOG3', 'LOG4', 'SELFDESTRUCT'}
# CALLCODE supplies a value context to this account; it is not a direct external payment.
VALUE_CALL_INDEX = {'CALL': 2}


@dataclass(frozen=True)
class Provenance:
    """Where a value may come from. `const` is set only when the value is provably a single constant."""

    caller: bool = False
    origin: bool = False
    storage: bool = False
    calldata: bool = False
    callresult: bool = False
    memory: bool = False
    const: Optional[int] = None
    const_known: bool = False

    def merge(self, other: 'Provenance') -> 'Provenance':
        const = self.const
        known = self.const_known and other.const_known
        if known and const != other.const:
            known = False
            const = None
        return Provenance(
            caller=self.caller or other.caller,
            origin=self.origin or other.origin,
            storage=self.storage or other.storage,
            calldata=self.calldata or other.calldata,
            callresult=self.callresult or other.callresult,
            memory=self.memory or other.memory,
            const=const,
            const_known=known,
        )

    @staticmethod
    def constant(value: int) -> 'Provenance':
        return Provenance(const=value, const_known=True)


@dataclass
class Condition:
    """A branch condition decomposed enough to say which edge is the authorised one."""

    caller: bool = False
    origin: bool = False
    relation: str = 'none'          # eq | ne | lt | gt | mixed | none
    identity: bool = False          # compares an identity credential
    identity_kind: str = ''         # storage | const | membership
    caller_vs_origin: bool = False
    limit: bool = False             # caller-dependent bounded comparison (e.g. a balance limit)
    limit_safe: Optional[bool] = None   # True when the bound rejects an over-withdrawal
    limit_inverted: bool = False    # the bound points the wrong way and admits an over-withdrawal
    authorized_true: Optional[bool] = None
    description: str = ''

    def merge(self, other: 'Condition') -> 'Condition':
        return Condition(
            caller=self.caller or other.caller,
            origin=self.origin or other.origin,
            relation='mixed' if self.relation != other.relation else self.relation,
            identity=self.identity or other.identity,
            identity_kind=self.identity_kind or other.identity_kind,
            caller_vs_origin=self.caller_vs_origin or other.caller_vs_origin,
            limit=self.limit or other.limit,
            limit_safe=self.limit_safe if self.limit_safe == other.limit_safe else None,
            limit_inverted=self.limit_inverted and other.limit_inverted,
            authorized_true=self.authorized_true if self.authorized_true == other.authorized_true else None,
            description=self.description or other.description,
        )


class FunctionView:
    """One function body: its blocks, its intra-procedural CFG and its dominators."""

    def __init__(self, facts, name: str):
        self.facts = facts
        self.name = name
        self.block_list: List[str] = list(facts.functions.get(name, []))
        self.blocks: Set[str] = set(self.block_list)
        if not self.blocks:
            raise KeyError('Unknown function: ' + name)
        self.partial = False
        self.entry = self._entry_block()
        self.successors: Dict[str, List[Tuple[str, Optional[bool]]]] = {}
        for block_id in sorted(self.blocks):
            self.successors[block_id] = self._edges(block_id)
        self.predecessors: Dict[str, Set[str]] = {block_id: set() for block_id in self.blocks}
        for source, edges in self.successors.items():
            for target, _ in edges:
                if target in self.blocks:
                    self.predecessors[target].add(source)
        self.dominators = self._dominators()

    # -- structure -----------------------------------------------------------------------------------
    def _entry_block(self) -> str:
        plain = [block_id for block_id in self.block_list
                 if len(self.facts.identifier_parts(block_id)) == 1]
        return plain[0] if plain else self.block_list[0]

    def instructions(self, block_id: str):
        return self.facts.blocks[block_id].instructions

    def _last(self, block_id: str):
        instructions = self.instructions(block_id)
        return instructions[-1] if instructions else None

    def _edges(self, block_id: str) -> List[Tuple[str, Optional[bool]]]:
        """Return (successor, polarity) where polarity is the JUMPI condition on that edge."""
        block = self.facts.blocks[block_id]
        declared = [s for s in block.successors if s in self.facts.blocks]
        last = self._last(block_id)
        if last is None:
            return [(s, None) for s in declared]
        if last.op == 'JUMPI' and len(last.uses) >= 2:
            target = resolve_constant(self.facts, last.uses[0])
            target_block = None
            if target is not None:
                for successor in declared:
                    if self.facts.original_address(successor) == target:
                        target_block = successor
                        break
            if target_block is None or len(declared) != 2:
                self.partial = True
                return [(s, None) for s in declared]
            edges = []
            for successor in declared:
                edges.append((successor, True if successor == target_block else False))
            return edges
        if last.op == 'JUMP' and declared:
            target = resolve_constant(self.facts, last.uses[0]) if last.uses else None
            if target is not None:
                matched = [s for s in declared if self.facts.original_address(s) == target]
                if matched:
                    return [(s, None) for s in matched]
            if len(declared) > 1:
                self.partial = True
            return [(s, None) for s in declared]
        return [(s, None) for s in declared]

    def _dominators(self) -> Dict[str, Set[str]]:
        nodes = self.blocks
        dom = {node: set(nodes) for node in nodes}
        dom[self.entry] = {self.entry}
        changed = True
        while changed:
            changed = False
            for node in sorted(nodes):
                if node == self.entry:
                    continue
                preds = self.predecessors[node]
                if not preds:
                    new = {node}
                else:
                    inter = None
                    for pred in preds:
                        inter = set(dom[pred]) if inter is None else (inter & dom[pred])
                    new = (inter or set()) | {node}
                if new != dom[node]:
                    dom[node] = new
                    changed = True
        return dom

    # -- traversals ----------------------------------------------------------------------------------
    def reachable(self, start: Iterable[str]) -> Set[str]:
        seen: Set[str] = set()
        stack = [s for s in start if s in self.blocks]
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            for successor, _ in self.successors.get(node, []):
                if successor in self.blocks and successor not in seen:
                    stack.append(successor)
        return seen

    def reachable_from_block(self, start: str, target: str) -> bool:
        if start not in self.blocks:
            return False
        return target in self.reachable([start])

    def call_sites(self) -> Iterable[Tuple[str, str]]:
        """(block id, callee function name) for every private call that resolves to a known function."""
        for block_id in sorted(self.blocks):
            for instruction in self.instructions(block_id):
                if instruction.op != 'CALLPRIVATE' or not instruction.uses:
                    continue
                target = resolve_constant(self.facts, instruction.uses[0])
                if target is None:
                    continue
                callee = self.facts.blocks.get('0x%x' % target)
                if callee is not None:
                    yield block_id, callee.function

    def terminal_blocks(self) -> Set[str]:
        return {block_id for block_id in self.blocks if not self.successors.get(block_id)}


def instruction_defining(facts, variable: str):
    """The instruction that defines a variable. Statement ids and variable names differ in cloned contexts."""
    index = getattr(facts, '_enforcement_next_defs', None)
    if index is None:
        index = {}
        for instruction in facts.instructions.values():
            for defined in instruction.defines:
                index.setdefault(defined, instruction)
        facts._enforcement_next_defs = index
    return index.get(variable)


def const_literals(facts) -> Dict[str, int]:
    """Literal values of CONST statements, parsed from the printed TAC.

    `TAC_Variable_Value.csv` only carries values the decompiler propagated; the literal in
    `v3b(0x8fc) = CONST` is otherwise absent, and constant folding needs it for zero tests and masks.
    """
    cached = getattr(facts, '_enforcement_next_literals', None)
    if cached is not None:
        return cached
    literals: Dict[str, int] = {}
    tac = Path(facts.directory) / 'contract.tac'
    if tac.is_file():
        pattern = re.compile(r'^\s*(\S+):\s*\S+\((0x[0-9a-fA-F]+)\)\s*=\s*CONST\s*$')
        for line in tac.read_text(encoding='utf8').splitlines():
            match = pattern.match(line)
            if match:
                literals[match.group(1)] = int(match.group(2), 16)
    facts._enforcement_next_literals = literals
    return literals


MAX_WORD = (1 << 256) - 1


def resolve_constant(facts, variable: str, depth: int = 0) -> Optional[int]:
    """Constant-fold a TAC operand with EVM word semantics.

    EVM arithmetic is modulo 2^256, `SHR` takes its shift amount as the *first* TAC operand and `DIV`/`MOD`
    by zero yield zero. Treating `SUB` as saturating at zero, or shifting by the wrong operand, silently
    changes every zero test and mask comparison that depends on the folded value.
    """
    if depth > 12 or not variable:
        return None
    if variable in facts.constants:
        return facts.constants[variable]
    instruction = instruction_defining(facts, variable)
    if instruction is None:
        return None
    op = instruction.op
    values = [resolve_constant(facts, use, depth + 1) for use in instruction.uses]
    if op == 'CONST':
        return const_literals(facts).get(instruction.id)
    if op == 'ISZERO' and values and values[0] is not None:
        return 1 if values[0] == 0 else 0
    if op == 'NOT' and values and values[0] is not None:
        return MAX_WORD ^ values[0]
    if len(values) < 2 or any(v is None for v in values):
        return None
    left, right = values[0], values[1]
    try:
        if op == 'AND':
            return left & right
        if op == 'OR':
            return left | right
        if op == 'XOR':
            return left ^ right
        if op == 'ADD':
            return (left + right) & MAX_WORD
        if op == 'SUB':
            return (left - right) & MAX_WORD
        if op == 'MUL':
            return (left * right) & MAX_WORD
        if op == 'DIV':
            return left // right if right else 0
        if op == 'MOD':
            return left % right if right else 0
        if op == 'SHR':
            return right >> left
        if op == 'SHL':
            return (right << left) & MAX_WORD
        if op == 'EXP':
            return pow(left, right, 1 << 256)
        if op == 'EQ':
            return 1 if left == right else 0
        if op == 'LT':
            return 1 if left < right else 0
        if op == 'GT':
            return 1 if left > right else 0
    except (ArithmeticError, ValueError):
        return None
    return None


def storage_read_key(facts, variable: str, depth: int = 0) -> Optional[str]:
    """The key operand of the storage read that produced `variable`, or None when it is not a storage read."""
    if depth > 6 or not variable:
        return None
    instruction = instruction_defining(facts, variable)
    if instruction is None or instruction.op != 'SLOAD' or not instruction.uses:
        return None
    return instruction.uses[0]


def expression_signature(facts, view: FunctionView, variable: str,
                         depth: int = 0) -> Optional[tuple]:
    """Structural identity of a TAC value, used to decide whether two expressions denote one storage slot.

    A mapping key is `keccak256(key . slot)`, so the key is not a variable identity but the material written
    into the hashed range. The signature therefore expands a `SHA3`/`KECCAK256` into the last write per
    constant offset inside that range, in statement order, and recurses into the written values. Two keys are
    the same slot only when the expanded material is the same; `SLOAD(caller)` and `SLOAD(caller + 1)` differ.
    Returns None when identity cannot be established, which callers must treat as "not proven".
    """
    if depth > 8 or not variable:
        return None
    instruction = instruction_defining(facts, variable)
    if instruction is None:
        return ('var', variable)
    op = instruction.op
    if op == 'CONST':
        value = resolve_constant(facts, variable)
        return ('const', value) if value is not None else ('var', variable)
    if op in {'SHA3', 'KECCAK256'}:
        return _hash_signature(facts, view, instruction, depth)
    parts: List[tuple] = []
    for use in instruction.uses:
        signature = expression_signature(facts, view, use, depth + 1)
        if signature is None:
            return None
        parts.append(signature)
    return (op, tuple(parts))


def _hash_signature(facts, view: FunctionView, instruction, depth: int) -> Optional[tuple]:
    if len(instruction.uses) < 2:
        return None
    offset = resolve_constant(facts, instruction.uses[0])
    size = resolve_constant(facts, instruction.uses[1])
    if offset is None or size is None:
        return None
    block = block_of_instruction(facts, view, instruction.id)
    if block is None:
        return None
    slot_values: Dict[int, Optional[tuple]] = {}
    for candidate in view.instructions(block):
        if candidate.id == instruction.id:
            break
        if candidate.op != 'MSTORE' or len(candidate.uses) < 2:
            continue
        at = resolve_constant(facts, candidate.uses[0])
        if at is None or not (offset <= at < offset + max(size, 32)):
            continue
        slot_values[at] = expression_signature(facts, view, candidate.uses[1], depth + 1)
    if not slot_values:
        return None
    material: List[tuple] = []
    for at in sorted(slot_values):
        value = slot_values[at]
        if value is None:
            return None
        material.append(value)
    return ('keccak', tuple(material))


def block_of_instruction(facts, view: FunctionView, instruction_id: str) -> Optional[str]:
    index = getattr(facts, '_enforcement_next_block_index', None)
    if index is None:
        index = {}
        for block_id in view.block_list:
            for instruction in view.instructions(block_id):
                index.setdefault(instruction.id, block_id)
        facts._enforcement_next_block_index = index
    return index.get(instruction_id)


def same_storage_slot(facts, view: FunctionView, left_key: str, right_key: str,
                      left_signature: Optional[tuple] = None) -> bool:
    """True only when the two key expressions provably denote the same storage slot."""
    if left_key == right_key:
        return True
    if left_signature is None:
        left_signature = expression_signature(facts, view, left_key)
    if left_signature is None:
        return False
    right_signature = expression_signature(facts, view, right_key)
    return right_signature is not None and right_signature == left_signature


def provenance_map(facts, view: FunctionView) -> Dict[str, Provenance]:
    """Forward union-based provenance with a fixpoint over the function body.

    A mapping key is `keccak256(key . slot)`, so the compiler writes the key to memory and hashes that range.
    The hash result therefore inherits the provenance of values stored in the same block. This is a
    block-local over-approximation: it never loses a caller/origin dependency, and it can attribute an
    unrelated stored value to a hash in the same block.
    """
    values: Dict[str, Provenance] = {}
    ordered = sorted(view.blocks)
    for _ in range(max(8, 2 * len(ordered))):
        changed = False
        for block_id in ordered:
            stored = Provenance()
            for instruction in view.instructions(block_id):
                merged = Provenance()
                for use in instruction.uses:
                    merged = merged.merge(values.get(use, Provenance()))
                if instruction.op == 'MSTORE' and len(instruction.uses) >= 2:
                    stored = stored.merge(values.get(instruction.uses[1], Provenance()))
                if instruction.op in {'SHA3', 'KECCAK256'} and len(instruction.uses) >= 2:
                    merged = merged.merge(stored)
                for defined in instruction.defines:
                    updated = _op_provenance(facts, instruction, merged)
                    if values.get(defined) != updated:
                        values[defined] = updated
                        changed = True
        if not changed:
            break
    return values


def _op_provenance(facts, instruction, merged: Provenance) -> Provenance:
    op = instruction.op
    if op in {'AND', 'OR', 'ADD', 'SUB', 'MUL', 'DIV', 'SHR', 'EXP', 'EQ', 'LT', 'GT', 'ISZERO'} \
            and instruction.defines:
        folded = resolve_constant(facts, instruction.defines[0])
        if folded is not None:
            return Provenance.constant(folded)
    if op == 'CONST':
        value = resolve_constant(facts, instruction.defines[0]) if instruction.defines else None
        return Provenance.constant(value) if value is not None else Provenance()
    if op == 'CALLER':
        return Provenance(caller=True)
    if op == 'ORIGIN':
        return Provenance(origin=True)
    if op in {'CALLDATALOAD', 'CALLDATASIZE', 'CALLVALUE'}:
        return Provenance(calldata=True)
    if op == 'SLOAD':
        return Provenance(storage=True).merge(merged)
    if op in {'MLOAD', 'RETURNDATASIZE', 'SELFBALANCE'}:
        return Provenance(memory=True)
    if op in EXTERNAL_CALL_OPS:
        return Provenance(callresult=True)
    return merged


def analyze_condition(facts, values: Dict[str, Provenance], variable: str,
                      depth: int = 0, negated: bool = False) -> Condition:
    """Decompose a branch condition into taint, relation and the polarity that means 'authorised'.

    `negated` carries the number of enclosing `ISZERO`s so that a relation is classified once, at the leaf,
    with the polarity the branch actually tests. That is what makes `amount <= balance` written as
    `LT(balance, amount)`, as `ISZERO(LT(balance, amount))`, as `LT(amount, balance)` or as
    `GT(amount, balance)` land on the same authorised edge instead of on the same edge *position*.
    """
    if depth > 8:
        return Condition(description='condition depth limit')
    provenance = values.get(variable, Provenance())
    base = Condition(caller=provenance.caller, origin=provenance.origin)
    instruction = instruction_defining(facts, variable)
    if instruction is None:
        return base
    op = instruction.op
    if op == 'ISZERO' and instruction.uses:
        inner = analyze_condition(facts, values, instruction.uses[0], depth + 1, not negated)
        return Condition(
            caller=inner.caller, origin=inner.origin, relation=inner.relation,
            identity=inner.identity, identity_kind=inner.identity_kind,
            caller_vs_origin=inner.caller_vs_origin, limit=inner.limit,
            limit_safe=inner.limit_safe, limit_inverted=inner.limit_inverted,
            authorized_true=inner.authorized_true,
            description='not(' + inner.description + ')',
        )
    if op in {'EQ', 'NE', 'LT', 'GT'} and len(instruction.uses) >= 2:
        left = values.get(instruction.uses[0], Provenance())
        right = values.get(instruction.uses[1], Provenance())
        return _relation(op, left, right, negated)
    if op in {'AND', 'OR'} and len(instruction.uses) >= 2:
        if negated:
            # De Morgan would be needed to name the authorised edge; abstain rather than guess.
            return Condition(caller=provenance.caller, origin=provenance.origin, relation='mixed',
                             description='negated conjunction')
        left = analyze_condition(facts, values, instruction.uses[0], depth + 1)
        right = analyze_condition(facts, values, instruction.uses[1], depth + 1)
        return left.merge(right)
    return base


def _relation(op: str, left: Provenance, right: Provenance, negated: bool = False) -> Condition:
    caller_vs_origin = ((left.caller and right.origin) or (left.origin and right.caller))
    caller_side = left.caller or right.caller
    origin_side = left.origin or right.origin
    relation = {'EQ': 'eq', 'NE': 'ne', 'LT': 'lt', 'GT': 'gt'}[op]
    condition = Condition(caller=caller_side, origin=origin_side, relation=relation)

    if caller_vs_origin:
        condition.caller_vs_origin = True
        condition.description = 'caller-vs-origin'
        if op == 'EQ':
            condition.authorized_true = not negated
        elif op == 'NE':
            condition.authorized_true = negated
        return condition

    # membership: a storage entry keyed by the caller/origin compared with zero (non-empty means present)
    for value, other in ((left, right), (right, left)):
        if value.storage and (value.caller or value.origin) and other.const_known and other.const == 0:
            condition.identity = True
            condition.identity_kind = 'membership'
            condition.authorized_true = (op == 'NE') != negated
            condition.description = '%s membership(storage)' % ('origin' if origin_side else 'caller')
            return condition

    # identity: an origin/caller value compared equal (or unequal) to a stored or declared credential. A
    # comparison against a calldata-derivable value is an amount test, and an ordering comparison against a
    # credential is not an identity test at all, so neither becomes an identity guard.
    if (caller_side or origin_side) and op in {'EQ', 'NE'}:
        credential = ''
        for value, other in ((left, right), (right, left)):
            if value.calldata or other.calldata:
                continue
            if value.storage and not value.caller and not value.origin:
                credential = 'storage'
            elif value.const_known and value.const not in (0, None) and not value.callresult:
                credential = 'const'
            if credential and (other.caller or other.origin):
                break
        if credential:
            condition.identity = True
            condition.identity_kind = credential
            authorized = (op == 'EQ')
            condition.authorized_true = authorized != negated
            condition.description = '%s %s identity(%s)' % (
                'origin' if origin_side and not caller_side else 'caller', relation, credential)
            return condition

    if caller_side and op in {'LT', 'GT'}:
        # `LT(a, b)` says a < b; normalise to (storage side, calldata side) so that the direction does not
        # depend on the operand order the compiler emitted.
        first, second = (left, right) if op == 'LT' else (right, left)
        kind = 'none'
        if first.storage and second.calldata:
            kind = 'over'          # balance < amount: the predicate *is* the over-withdrawal test
        elif first.calldata and second.storage:
            kind = 'under'         # amount < balance: the predicate holds only within the limit
        if kind == 'over':
            condition.limit = True
            condition.limit_safe = True
            condition.authorized_true = bool(negated)
            condition.description = 'balance below amount (%s)' % (
                'authorised when false' if not negated else 'authorised when true')
        elif kind == 'under':
            condition.limit = True
            if negated:
                # not(amount < balance) is amount >= balance, which admits an over-withdrawal
                condition.limit_safe = False
                condition.limit_inverted = True
                condition.authorized_true = None
                condition.description = 'inverted limit (amount >= balance)'
            else:
                condition.limit_safe = True
                condition.authorized_true = True
                condition.description = 'amount below balance (authorised when true)'
    return condition


@dataclass
class Guard:
    block: str
    condition: Condition
    authorized_true: bool            # True when the JUMPI's true edge is the authorised outcome

    def edge_is_authorized(self, polarity: Optional[bool]) -> Optional[bool]:
        if polarity is None:
            return None
        return polarity == self.authorized_true
