"""Check authority over the account actually debited, using declared storage layout.

This is an opt-in token requirement, not a rule that every public state mutation
needs an owner. It checks net balance decreases at a known balance mapping. A
third-party debit requires enough initial allowance AND its consumption for the
same holder/spender pair. Unknown storage shapes and external calls remain unknown.
It says nothing about minting or cross-chain supply conservation.
"""
from __future__ import annotations

import z3 as z


def debit_condition(engine, state, policy):
    from .engine import B, Engine, bv, simple

    balance_slot = int(policy["balance_slot"])
    allowance_slot = int(policy["allowance_slot"])
    if balance_slot == allowance_slot:
        raise ValueError("balance and allowance mappings must have distinct slots")
    terms = []
    debits = []
    seen = set()
    unavailable = bool(state.calls)  # Calls could change storage/reenter; this component does not model that.
    hash64 = engine.hash_functions.setdefault(64, z.Function("keccak_64", B, B, B))
    caller = Engine._as_160(engine.caller)
    for instruction, raw_key, _ in state.writes:
        key = simple(raw_key)
        if not z.is_app(key) or key.decl().name() != "keccak_64" or key.num_args() != 2:
            if not z.is_bv_value(key):
                unavailable = True
            continue
        slot = simple(key.arg(1))
        if not z.is_bv_value(slot):
            # Recognised nested mappings are not single-level balance entries.
            if not Engine._nested_entries(key):
                unavailable = True
            continue
        if slot.as_long() != balance_slot or key.sexpr() in seen:
            continue
        seen.add(key.sexpr())
        holder = Engine._as_160(key.arg(0))
        before = z.Select(engine.initial_storage, key)
        after = z.Select(state.storage, key)
        amount = before - after
        allowance_key = hash64(z.ZeroExt(96, caller), hash64(z.ZeroExt(96, holder), bv(allowance_slot)))
        initial_allowance = z.Select(engine.initial_storage, allowance_key)
        final_allowance = z.Select(state.storage, allowance_key)
        authorised = z.And(z.UGE(initial_allowance, amount),
                           final_allowance == initial_allowance - amount)
        if policy.get("unlimited_allowance"):
            authorised = z.Or(authorised, initial_allowance == bv((1 << 256) - 1))
        condition = z.And(z.UGT(before, after), holder != caller, z.Not(authorised))
        terms.append(condition)
        debits.append({"instruction": instruction, "balance_key": str(key),
                       "holder": str(holder), "debit": str(simple(amount)),
                       "allowance_key": str(allowance_key)})
    return z.Or(*terms), bool(debits), unavailable, debits
