"""Run the three property rules over one runtime's Gigahorse facts and aggregate verdicts.

Input: a facts directory. Output: one status per SWC property with evidence. No label, contract name,
provider or expected result is read.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from implementation.enforcement.facts import Facts

from .rules import (
    Obligation,
    call_result_obligations,
    ether_transfer_obligations,
    guards_of,
    origin_obligations,
    _protection,
)
from .tac import EXTERNAL_CALL_OPS, FunctionView, provenance_map

PROPERTIES = ('104', '105', '115')
FLAG_NAMES = ('callresult_dependency', 'origin_role', 'guard_dominance')

DEFAULT_FLAGS = {name: True for name in FLAG_NAMES}


def analyse_facts(facts_dir, flags: Optional[Dict[str, bool]] = None) -> Dict[str, object]:
    flags = dict(DEFAULT_FLAGS, **(flags or {}))
    started = time.monotonic()
    try:
        facts = Facts(facts_dir)
    except Exception as error:                                  # noqa: BLE001 - recorded, never hidden
        return {'status': 'error', 'error': '%s: %s' % (type(error).__name__, error),
                'flags': flags, 'properties': {}}

    public_entries = []
    for entry, selector in sorted(facts.public.items()):
        block = facts.blocks.get(entry)
        if block is None:
            continue
        public_entries.append({'entry_block': entry, 'selector': selector, 'function': block.function})
    if not public_entries:
        return {'status': 'error', 'error': 'No public function dispatch found',
                'flags': flags, 'properties': {}}

    reachable_functions: List[str] = []
    seen_functions: Set[str] = set()
    partial = False
    for entry in public_entries:
        if entry['function'] in seen_functions:
            continue
        seen_functions.add(entry['function'])
        reachable_functions.append(entry['function'])

    obligations: Dict[str, List[Obligation]] = {name: [] for name in PROPERTIES}
    incomplete: Dict[str, bool] = {name: False for name in PROPERTIES}
    coverage: Dict[str, object] = {'public_entries': public_entries, 'functions': {}, 'partial_functions': []}
    queue = list(reachable_functions)
    analysed: Set[str] = set()
    while queue:
        name = queue.pop(0)
        if name in analysed:
            continue
        analysed.add(name)
        try:
            view = FunctionView(facts, name)
        except Exception as error:                              # noqa: BLE001
            coverage['functions'][name] = {'error': str(error)}
            for swc in PROPERTIES:
                incomplete[swc] = True
            continue
        values = provenance_map(facts, view)
        has_call = any(instruction.op in EXTERNAL_CALL_OPS
                       for block_id in view.blocks for instruction in view.instructions(block_id))
        has_origin = any(instruction.op == 'ORIGIN'
                         for block_id in view.blocks for instruction in view.instructions(block_id))
        coverage['functions'][name] = {
            'blocks': len(view.blocks), 'entry': view.entry, 'partial': view.partial,
            'external_calls': has_call, 'origin': has_origin,
        }
        if view.partial:
            partial = True
            coverage['partial_functions'].append(name)
            if has_call:
                incomplete['104'] = True
                incomplete['105'] = True
            if has_origin:
                incomplete['115'] = True
        obligations['104'].extend(call_result_obligations(facts, view, flags))
        obligations['115'].extend(origin_obligations(facts, view, flags))
        for call_block, callee in view.call_sites():
            if callee not in analysed:
                queue.append(callee)

    ether_obligations, ether_partial = _ether_walk(facts, reachable_functions, flags)
    obligations['105'].extend(ether_obligations)
    if ether_partial:
        partial = True
        incomplete['105'] = True

    results = {}
    for swc in PROPERTIES:
        rows = obligations[swc]
        status = _aggregate(rows, incomplete[swc])
        results[swc] = {
            'status': status,
            'reason': _dominant_reason(rows, status),
            'evidence': [{'status': row.status, 'reason': row.reason, 'evidence': row.evidence}
                         for row in rows][:40],
            'obligations': len(rows),
        }
    return {
        'status': 'ok',
        'flags': flags,
        'elapsed_seconds': round(time.monotonic() - started, 3),
        'facts': {
            'blocks': len(facts.blocks), 'instructions': len(facts.instructions),
            'functions': len(facts.functions), 'public_functions': len(facts.public),
            'unmapped_operations': facts.unmapped_operations,
            'missing_edges': len(facts.missing_edges),
        },
        'coverage': coverage,
        'properties': results,
    }


def _ether_walk(facts, entries: List[str], flags: Dict[str, bool]) -> Tuple[List[Obligation], bool]:
    obligations: List[Obligation] = []
    partial = False
    visited: Set[Tuple[str, Tuple[str, ...]]] = set()
    stack: List[Tuple[str, List]] = [(name, []) for name in entries]
    while stack:
        name, inherited = stack.pop()
        key = (name, tuple(sorted(guard.block for guard in inherited)))
        if key in visited:
            continue
        visited.add(key)
        view = FunctionView(facts, name)
        values = provenance_map(facts, view)
        obligations.extend(ether_transfer_obligations(facts, view, flags, inherited))
        if view.partial:
            partial = True
        guards = guards_of(facts, view, values)
        for call_block, callee in view.call_sites():
            passed = [guard for guard in guards
                      if guard.block in view.dominators.get(call_block, set())
                      and str(_protection(facts, view, [guard], [], call_block)) == 'protected']
            stack.append((callee, inherited + passed))
    return obligations, partial


def _aggregate(rows: List[Obligation], incomplete: bool) -> str:
    if any(row.status == 'positive' for row in rows):
        return 'positive'
    if any(row.status == 'unknown' for row in rows):
        return 'unknown'
    if incomplete:
        return 'unknown'
    if rows:
        return 'negative'
    return 'negative'


def _dominant_reason(rows: List[Obligation], status: str) -> str:
    for row in rows:
        if row.status == status:
            return row.reason
    if status == 'unknown':
        return 'analysis did not complete the property scope'
    return 'no obligation reached the positive condition'
