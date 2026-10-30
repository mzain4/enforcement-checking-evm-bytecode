"""Conservative, field-sensitive credential-write candidates; never reads labels or source names.

This extends local transfer protection with public-entry credential integrity. It is a candidate pattern
analysis, not a proof of feasible execution or safety for arbitrary storage/delegation contexts.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import time

from implementation.enforcement.facts import Facts
from implementation.enforcement_next.analyze import analyse_facts as base_analyse
from implementation.enforcement_next.rules import _caller_bound, _protection, branch_conditions, guards_of
from implementation.enforcement_next.tac import (
    FunctionView, VALUE_CALL_INDEX, instruction_defining, provenance_map, resolve_constant,
)

WORD = (1 << 256) - 1
ADDRESS = (1 << 160) - 1


def unsupported_instructions(code, capabilities=None):
    """Known frontend capability gaps, scanning instructions rather than PUSH data/CBOR metadata."""
    capabilities = capabilities or {}
    if code.startswith(b'\xef\x01\x00'):
        return ['delegation indicator needs resolved account context']
    if code.startswith(b'\xef\x00'):
        return ['EOF container not supported by this frontend']
    # Some released inputs append more than one compiler metadata trailer.
    # Peel each recognizable trailer; their bytes are not EVM instructions.
    while len(code) >= 3:
        size = int.from_bytes(code[-2:], 'big')
        if 0 < size < len(code) - 2:
            suffix = code[-size-2:-2]
            if 0xa0 <= suffix[0] <= 0xbf and any(k in suffix for k in (b'solc', b'ipfs', b'bzzr')):
                code = code[:-size-2]
                continue
        break
    gaps = set()
    pc = 0
    while pc < len(code):
        op = code[pc]
        if op == 0x5f and not capabilities.get('push0'):
            gaps.add('PUSH0 not modeled by inherited frontend')
        if op in {0x5c, 0x5d, 0x5e}:
            gaps.add({0x5c: 'TLOAD', 0x5d: 'TSTORE', 0x5e: 'MCOPY'}[op] + ' not validated in this frontend')
        pc += op - 0x5f + 1 if 0x60 <= op <= 0x7f else 1
    return sorted(gaps)


def bits(facts, variable, depth=0):
    """(attacker-controlled, known-zero, known-one) masks for a small unsigned expression fragment.

    A controlled bit is established only through caller/calldata and supported bitwise/copy operations.
    Unknown other operands never supply a controllability proof. In particular, OR with old storage
    preserves controllability only where the other operand is known zero.
    """
    if depth > 24:
        return 0, 0, 0
    constant = resolve_constant(facts, variable)
    if constant is not None:
        return 0, WORD ^ (constant & WORD), constant & WORD
    op = instruction_defining(facts, variable)
    if op is None:
        return 0, 0, 0
    if op.op == 'CALLER':
        return ADDRESS, WORD ^ ADDRESS, 0
    if op.op == 'CALLDATALOAD':
        return WORD, 0, 0
    if op.op in {'AND', 'OR', 'XOR'} and len(op.uses) == 2:
        ac, az, ao = bits(facts, op.uses[0], depth + 1)
        bc, bz, bo = bits(facts, op.uses[1], depth + 1)
        if op.op == 'AND':
            return ((ac & bo) | (bc & ao)), az | bz, ao & bo
        if op.op == 'OR':
            return ((ac & bz) | (bc & az)), az & bz, ao | bo
        return ((ac & (bz | bo)) | (bc & (az | ao))), (az & bz) | (ao & bo), (az & bo) | (ao & bz)
    if op.op in {'SHL', 'SHR'} and len(op.uses) == 2:
        amount = resolve_constant(facts, op.uses[0])
        if amount is not None and 0 <= amount < 256:
            c, z, o = bits(facts, op.uses[1], depth + 1)
            if op.op == 'SHL':
                return (c << amount) & WORD, ((z << amount) | ((1 << amount) - 1)) & WORD, (o << amount) & WORD
            fill = WORD ^ (WORD >> amount)
            return c >> amount, (z >> amount) | fill, o >> amount
    if op.op in {'MUL', 'DIV'} and len(op.uses) == 2:
        options = [(op.uses[1], op.uses[0])]
        if op.op == 'MUL':
            options.append((op.uses[0], op.uses[1]))
        for literal, value in options:
            factor = resolve_constant(facts, literal)
            if factor == 0:
                return 0, WORD, 0
            if factor is not None and factor > 0 and factor & (factor - 1) == 0:
                amount = factor.bit_length() - 1
                c, z, o = bits(facts, value, depth + 1)
                if op.op == 'MUL':
                    return (c << amount) & WORD, ((z << amount) | ((1 << amount) - 1)) & WORD, (o << amount) & WORD
                fill = WORD ^ (WORD >> amount)
                return c >> amount, (z >> amount) | fill, o >> amount
    if op.op in {'COPY', 'MOV', 'ASSIGN'} and len(op.uses) == 1:
        return bits(facts, op.uses[0], depth + 1)
    if op.op == 'PHI' and op.uses:
        values = [bits(facts, v, depth + 1) for v in op.uses]
        result = [WORD, WORD, WORD]
        for value in values:
            result = [a & b for a, b in zip(result, value)]
        return tuple(result)
    return 0, 0, 0


def storage_field(facts, variable, mask=ADDRESS, depth=0):
    """Constant storage slot and relevant input-bit mask; no hashed/dynamic alias guesses."""
    if depth > 20:
        return None
    op = instruction_defining(facts, variable)
    if op is None:
        return None
    if op.op == 'SLOAD' and op.uses:
        slot = resolve_constant(facts, op.uses[0])
        return (slot, mask & WORD) if slot is not None and mask else None
    if op.op == 'AND' and len(op.uses) == 2:
        for a, b in (op.uses, op.uses[::-1]):
            constant = resolve_constant(facts, a)
            if constant is not None:
                return storage_field(facts, b, mask & constant, depth + 1)
    if op.op in {'SHR', 'SHL'} and len(op.uses) == 2:
        shift = resolve_constant(facts, op.uses[0])
        if shift is not None and 0 <= shift < 256:
            before = (mask << shift) & WORD if op.op == 'SHR' else mask >> shift
            return storage_field(facts, op.uses[1], before, depth + 1)
    if op.op == 'DIV' and len(op.uses) == 2:
        divisor = resolve_constant(facts, op.uses[1])
        if divisor and divisor & (divisor - 1) == 0:
            return storage_field(facts, op.uses[0], (mask << (divisor.bit_length() - 1)) & WORD, depth + 1)
    if op.op in {'COPY', 'MOV', 'ASSIGN'} and len(op.uses) == 1:
        return storage_field(facts, op.uses[0], mask, depth + 1)
    return None


def dynamic_slot(facts, view, block, variable, depth=0):
    """`(base slot, key variable)` for a compiler-emitted `keccak256(key . base)` mapping slot.

    A Solidity mapping is addressed by hashing a 64-byte memory image whose first word is the key and whose
    second word is the declaration slot. The image is recovered only from constant-offset `MSTORE`
    instructions that precede the hash inside the same block; anything else stays unproven rather than guessed.
    """
    if depth > 8:
        return None
    op = instruction_defining(facts, variable)
    if op is None:
        return None
    if op.op in {'COPY', 'MOV', 'ASSIGN'} and len(op.uses) == 1:
        return dynamic_slot(facts, view, block, op.uses[0], depth + 1)
    if op.op != 'SHA3' or len(op.uses) != 2:
        return None
    offset = resolve_constant(facts, op.uses[0])
    size = resolve_constant(facts, op.uses[1])
    if offset is None or size != 0x40:
        return None
    sequence = list(view.instructions(block))
    position = next((index for index, item in enumerate(sequence) if item.id == op.id), None)
    if position is None:
        return None
    key = base = None
    for index, item in enumerate(sequence):
        if index >= position:
            break
        if item.op != 'MSTORE' or len(item.uses) != 2:
            continue
        at = resolve_constant(facts, item.uses[0])
        if at == offset:
            key = item.uses[1]
        elif at == offset + 0x20:
            base = item.uses[1]
    base_value = resolve_constant(facts, base) if base else None
    if key is None or base_value is None:
        return None
    return base_value, key


def guard_dynamic_credential(facts, view, guard, values):
    """`(base slot, key variable)` when a guard reads a caller-keyed mapping entry; else None."""
    if not (guard.condition.identity and guard.condition.identity_kind == 'membership'):
        return None
    found = set()
    for op in view.instructions(guard.block):
        if op.op != 'SLOAD' or not op.uses:
            continue
        source = values.get(op.defines[0]) if op.defines else None
        if source is None or not (source.storage and source.caller):
            continue
        resolved = dynamic_slot(facts, view, guard.block, op.uses[0])
        if resolved is not None:
            found.add(resolved)
    return next(iter(found)) if len(found) == 1 else None


def key_control(values, variable):
    """How the attacker reaches a mapping key: free choice, its own address, or not at all."""
    source = values.get(variable)
    if source is None:
        return None
    if source.calldata:
        return 'chosen'
    if source.caller:
        return 'self'
    return None


def credential_field(facts, view, guard, values):
    if not (guard.condition.identity and guard.condition.identity_kind == 'storage' and guard.condition.caller):
        return None
    jump = view.instructions(guard.block)[-1]
    variable = jump.uses[1]
    for _ in range(10):
        op = instruction_defining(facts, variable)
        if op is None:
            return None
        if op.op == 'ISZERO' and op.uses:
            variable = op.uses[0]
            continue
        if op.op not in {'EQ', 'NE'} or len(op.uses) != 2:
            return None
        for a, b in (op.uses, op.uses[::-1]):
            provenance = values.get(a)
            if provenance and provenance.caller and not provenance.storage and not provenance.calldata:
                return storage_field(facts, b)
        return None
    return None


def public_views(facts):
    names = sorted({facts.blocks[b].function for b in facts.public if b in facts.blocks})
    return [FunctionView(facts, name) for name in names if name != '__function_selector__']


def calldata_only_condition(facts, values, variable, depth=0):
    """True when a branch condition constrains only caller-supplied data against constants.

    `require(_owner != 0)` forbids the zero address; it does not stop a caller choosing its own non-zero
    key, so it is a well-formedness check rather than an authorization restriction.
    """
    if depth > 6 or not variable:
        return False
    op = instruction_defining(facts, variable)
    if op is None:
        return False
    if op.op in {'ISZERO', 'NOT'} and op.uses:
        return calldata_only_condition(facts, values, op.uses[0], depth + 1)
    if op.op not in {'EQ', 'NE', 'LT', 'GT'} or len(op.uses) != 2:
        return False
    for operand in op.uses:
        source = values.get(operand)
        if source is None:
            folded = resolve_constant(facts, operand)
            if folded is None:
                return False
            continue
        if source.storage or source.caller or source.origin or source.callresult:
            return False
        if not (source.calldata or source.const_known):
            return False
    return True


def writer_status(facts, view, block, values):
    """An unresolved/initialization branch is not treated as an unrestricted credential setter."""
    if view.partial:
        return 'unknown', 'partial function'
    for guard in guards_of(facts, view, values):
        if guard.condition.identity and _protection(facts, view, [guard], [], block) == 'protected':
            return 'guarded', guard.condition.description
    for branch, var, condition in branch_conditions(facts, view, values):
        if branch not in view.dominators.get(block, set()):
            continue
        # Only an ordinary no-value compiler guard is discharged here; ABI/other conditions stay unresolved.
        op = instruction_defining(facts, var)
        if op and op.op == 'ISZERO' and op.uses:
            source = instruction_defining(facts, op.uses[0])
            if source and source.op == 'CALLVALUE':
                continue
        if calldata_only_condition(facts, values, var):
            continue
        return 'unknown', 'conditional public write: ' + condition.description
    if list(view.call_sites()) or any(op.op in {'CALL', 'STATICCALL', 'DELEGATECALL', 'CALLCODE', 'CALLPRIVATE'}
           for b in view.blocks for op in view.instructions(b)):
        return 'unknown', 'write entry has unresolved call context'
    return 'unrestricted', 'no dominating authorization/state condition in supported entry'


def credential_candidates(facts, membership=True):
    views = public_views(facts)
    writers = []
    dynamic_writers = []
    for view in views:
        values = provenance_map(facts, view)
        for block in sorted(view.blocks):
            for op in view.instructions(block):
                if op.op != 'SSTORE' or len(op.uses) != 2:
                    continue
                slot = resolve_constant(facts, op.uses[0])
                controlled = bits(facts, op.uses[1])[0]
                if slot is None:
                    mapping = dynamic_slot(facts, view, block, op.uses[0])
                    if mapping is None or not controlled:
                        continue
                    base, key = mapping
                    control = key_control(values, key)
                    if control is None:
                        continue
                    status, reason = writer_status(facts, view, block, values)
                    dynamic_writers.append({'function': view.name, 'block': block, 'instruction': op.id,
                        'dynamic_base': base, 'key_control': control, 'key_variable': key,
                        'controlled_mask': controlled, 'status': status, 'reason': reason})
                    continue
                if not controlled:
                    continue
                status, reason = writer_status(facts, view, block, values)
                writers.append({'function': view.name, 'block': block, 'instruction': op.id,
                    'slot': slot, 'controlled_mask': controlled, 'status': status, 'reason': reason})
    candidates = []
    diagnostics = []
    # The initial extension intentionally supports direct public transfer bodies. Private effects are reported
    # as outside this new obligation's scope, while the unchanged base checker still analyzes them.
    for view in views:
        if view.partial:
            continue
        values = provenance_map(facts, view)
        guards = guards_of(facts, view, values)
        for block in sorted(view.blocks):
            for op in view.instructions(block):
                if op.op not in VALUE_CALL_INDEX or len(op.uses) <= VALUE_CALL_INDEX[op.op]:
                    continue
                if resolve_constant(facts, op.uses[VALUE_CALL_INDEX[op.op]]) == 0:
                    continue
                if _caller_bound(facts, view, values, op)[0] == 'consumed':
                    continue
                protecting = [g for g in guards if g.block in view.dominators.get(block, set()) and
                               _protection(facts, view, [g], [], block) == 'protected']
                identities = [g for g in protecting if g.condition.identity]
                fields = [credential_field(facts, view, g, values) for g in identities]
                if not identities or any(f is None for f in fields):
                    continue
                slots = {f[0] for f in fields}
                if len(slots) != 1:
                    continue
                mask = 0
                for _, field_mask in fields:
                    mask |= field_mask
                slot = next(iter(slots))
                matches = [w for w in writers if w['slot'] == slot and
                           w['controlled_mask'] & mask == mask]
                diagnostics.append({'function': view.name, 'effect': op.id, 'slot': slot,
                                    'credential_mask': hex(mask), 'matching_writes': matches})
                for writer in matches:
                    if writer['status'] == 'guarded':
                        continue
                    status = 'positive' if writer['status'] == 'unrestricted' else 'unknown'
                    candidates.append({'status': status, 'reason':
                        'public entry can overwrite the complete guarding credential field' if status == 'positive'
                        else 'credential write has unresolved authorization/state context',
                        'evidence': {'effect_function': view.name, 'effect': op.id,
                                     'credential_slot': slot, 'credential_mask': hex(mask),
                                     'writer': writer, 'guard_blocks': [g.block for g in identities],
                                     'scope': 'candidate over lifted facts; initial-state/path feasibility not proved'}})

    # Dynamic keyed credentials: a caller-keyed membership entry, written by an entry that lets the caller
    # choose the key (or use its own address), moves the credential the guard reads. A fixed key cannot.
    membership_effects = []
    for view in (views if membership else []):
        if view.partial:
            continue
        values = provenance_map(facts, view)
        guards = guards_of(facts, view, values)
        for block in sorted(view.blocks):
            for op in view.instructions(block):
                if op.op not in VALUE_CALL_INDEX or len(op.uses) <= VALUE_CALL_INDEX[op.op]:
                    continue
                if resolve_constant(facts, op.uses[VALUE_CALL_INDEX[op.op]]) == 0:
                    continue
                if _caller_bound(facts, view, values, op)[0] == 'consumed':
                    continue
                protecting = [g for g in guards if g.block in view.dominators.get(block, set()) and
                              _protection(facts, view, [g], [], block) == 'protected']
                keyed = [guard_dynamic_credential(facts, view, g, values) for g in protecting]
                keyed = [k for k in keyed if k is not None]
                if not keyed:
                    continue
                bases = {k[0] for k in keyed}
                if len(bases) != 1:
                    continue
                base = next(iter(bases))
                matches = [w for w in dynamic_writers if w['dynamic_base'] == base]
                membership_effects.append({'function': view.name, 'effect': op.id, 'dynamic_base': base,
                                   'matching_writes': matches})
                for writer in matches:
                    if writer['status'] == 'guarded':
                        continue
                    status = 'positive' if writer['status'] == 'unrestricted' else 'unknown'
                    candidates.append({'status': status, 'reason':
                        'public entry can set the caller-keyed membership credential the guard reads'
                        if status == 'positive' else
                        'membership credential write has unresolved authorization/state context',
                        'evidence': {'effect_function': view.name, 'effect': op.id,
                                     'dynamic_base': base, 'key_control': writer['key_control'],
                                     'writer': writer, 'guard_blocks': [g.block for g in protecting],
                                     'scope': 'candidate over lifted facts; initial-state/path feasibility not proved'}})

    return candidates, {'writers': writers, 'dynamic_writers': dynamic_writers,
                         'credential_effects': diagnostics, 'membership_effects': membership_effects,
                         'public_functions': len(views), 'private_effect_support': False}


def analyse_facts(directory, *, credential_integrity=True, base_flags=None, membership_credential=True):
    start = time.monotonic()
    directory = Path(directory)
    raw = directory / 'bytecode.hex'
    capabilities_path = directory / 'frontend-capabilities.json'
    capabilities = json.loads(capabilities_path.read_text()) if capabilities_path.is_file() else {}
    if raw.is_file():
        try:
            gaps = unsupported_instructions(bytes.fromhex(''.join(raw.read_text().split()).removeprefix('0x')), capabilities)
        except ValueError:
            gaps = ['invalid raw runtime bytes']
        if gaps:
            return {'status': 'unsupported', 'reason': '; '.join(gaps),
                    'credential_integrity_enabled': credential_integrity,
                    'properties': {p: {'status': 'unsupported', 'reason': '; '.join(gaps), 'evidence': []}
                                   for p in ('104', '105', '115')}}
    result = copy.deepcopy(base_analyse(directory, base_flags))
    result['frontend_capabilities'] = capabilities
    result['credential_integrity_enabled'] = credential_integrity
    if result.get('status') != 'ok':
        return result
    if credential_integrity:
        try:
            candidates, diagnostics = credential_candidates(Facts(directory), membership=membership_credential)
            result['credential_analysis'] = diagnostics
            result['membership_credential_enabled'] = membership_credential
            result['credential_candidates'] = candidates
            if candidates:
                prop = result['properties']['105']
                positive = [c for c in candidates if c['status'] == 'positive']
                if positive or prop['status'] != 'positive':
                    prop['status'] = 'positive' if positive else 'unknown'
                    prop['reason'] = (positive or candidates)[0]['reason']
                prop['evidence'] = candidates + prop['evidence']
                prop['obligations'] += len(candidates)
        except Exception as error:
            result['credential_analysis_error'] = type(error).__name__ + ': ' + str(error)
            if result['properties']['105']['status'] == 'negative':
                result['properties']['105']['status'] = 'unknown'
                result['properties']['105']['reason'] = 'credential analysis failed'
    result['elapsed_seconds'] = round(time.monotonic() - start, 6)
    return result
