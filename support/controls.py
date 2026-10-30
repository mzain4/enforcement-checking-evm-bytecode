"""Authored credential-field controls. These are development programs, not independent test labels."""
from pathlib import Path
from implementation.enforcement_next.controls import FactsBuilder

ADDRESS = (1 << 160) - 1
WORD = (1 << 256) - 1
CASES = {
    'caller_setter': ('positive', 'unrestricted caller assignment'),
    'calldata_setter': ('positive', 'unrestricted chosen identity'),
    'shifted_setter': ('positive', 'credential occupies upper 160 bits'),
    'multiply_setter': ('positive', 'older compiler uses multiplication/division for field placement'),
    'guarded_setter': ('negative', 'role change requires current owner'),
    'fixed_guard_setter': ('negative', 'role change requires fixed manager'),
    'packed_neighbor': ('negative', 'unrelated upper field shares storage word'),
    'no_setter': ('negative', 'no public credential writer'),
    'two_credentials': ('negative', 'second independent credential still protects'),
    'initialization_gate': ('unknown', 'initialization state is not known from runtime'),
    'external_call_setter': ('unknown', 'setter calls external code before writing'),
    'partial_field': ('negative', 'writer does not control the complete identity field'),
    'or_unknown_storage': ('negative', 'unmasked old bits do not establish complete control'),
}


class ValueBuilder(FactsBuilder):
    def stmt(self, statement_id, op, uses=None, defines=None, literal=None):
        super().stmt(statement_id, op, uses, defines, literal)
        return defines[0] if defines else statement_id


def build(directory: Path, case: str, split_write=False, rename=False):
    b = ValueBuilder()
    b.function('__function_selector__', '0x00000000').block('0x1', [])
    b.stmt('0x2', 'STOP')
    b.function('withdraw', '0x11111111').block('0x10', ['0x20', '0x30'])
    slot = b.stmt('0x1000', 'CONST', defines=['vslot'], literal=0)
    owner = b.stmt('0x1001', 'SLOAD', uses=[slot], defines=['vowner'])
    if case in {'shifted_setter', 'multiply_setter'}:
        shift = b.stmt('0x1002', 'CONST', defines=['vshift'], literal=96)
        if case == 'multiply_setter':
            power = b.stmt('0x100b', 'CONST', defines=['vpower'], literal=1 << 96)
            owner = b.stmt('0x1003', 'DIV', uses=[owner, power], defines=['vowner_shift'])
        else:
            owner = b.stmt('0x1003', 'SHR', uses=[shift, owner], defines=['vowner_shift'])
    mask = b.stmt('0x1004', 'CONST', defines=['vmask'], literal=ADDRESS)
    owner = b.stmt('0x1005', 'AND', uses=[owner, mask], defines=['vcredential'])
    caller = b.stmt('0x1006', 'CALLER', defines=['vcaller'])
    z = b.stmt('0x100a', 'CONST', defines=['vzero'], literal=0)
    equal = b.stmt('0x1007', 'EQ', uses=[caller, owner], defines=['vequal'])
    target = b.stmt('0x1008', 'CONST', defines=['vtarget'], literal=0x20)
    b.stmt('0x1009', 'JUMPI', uses=[target, equal])
    b.block('0x30', [])
    b.stmt('0x1011', 'REVERT', uses=[z, z])
    if case == 'two_credentials':
        b.block('0x20', ['0x40', '0x50'])
        key = b.stmt('0x1020', 'CONST', defines=['vslot2'], literal=1)
        second = b.stmt('0x1021', 'SLOAD', uses=[key], defines=['vsecond'])
        cond = b.stmt('0x1022', 'EQ', uses=[caller, second], defines=['veq2'])
        jump = b.stmt('0x1023', 'CONST', defines=['vjump2'], literal=0x40)
        b.stmt('0x1024', 'JUMPI', uses=[jump, cond])
        b.block('0x50', []).stmt('0x1025', 'REVERT', uses=[z, z])
        b.block('0x40', [])
    else:
        b.block('0x20', [])
    gas = b.stmt('0x1030', 'CONST', defines=['vgas'], literal=100000)
    amount = b.stmt('0x1031', 'SELFBALANCE', defines=['vamount'])
    b.stmt('0x1032', 'CALL', uses=[gas, caller, amount, z, z, z, z], defines=['vok'])
    b.stmt('0x1033', 'STOP')
    if case == 'no_setter':
        return b.emit(directory)
    b.function('update', '0x22222222')
    conditional = case in {'guarded_setter', 'fixed_guard_setter', 'initialization_gate'}
    b.block('0x60', ['0x70', '0x80'] if conditional else [])
    key = b.stmt('0x2000', 'CONST', defines=['wslot'], literal=0)
    old = b.stmt('0x2001', 'SLOAD', uses=[key], defines=['wold'])
    who = b.stmt('0x2002', 'CALLER', defines=['wwho'])
    wz = b.stmt('0x2003', 'CONST', defines=['wzero'], literal=0)
    if conditional:
        if case == 'initialization_gate':
            ikey = b.stmt('0x2010', 'CONST', defines=['wik'], literal=1)
            iv = b.stmt('0x2011', 'SLOAD', uses=[ikey], defines=['winit'])
            cond = b.stmt('0x2012', 'ISZERO', uses=[iv], defines=['wcond'])
        else:
            identity = old
            if case == 'fixed_guard_setter':
                identity = b.stmt('0x2013', 'CONST', defines=['wmanager'], literal=0x123456789)
            cond = b.stmt('0x2014', 'EQ', uses=[who, identity], defines=['wcond'])
        jump = b.stmt('0x2015', 'CONST', defines=['wtarget'], literal=0x70)
        b.stmt('0x2016', 'JUMPI', uses=[jump, cond])
        b.block('0x80', []).stmt('0x2017', 'REVERT', uses=[wz, wz])
        b.block('0x70', [])
    value = who
    if case == 'calldata_setter':
        offset = b.stmt('0x2020', 'CONST', defines=['woff'], literal=4)
        value = b.stmt('0x2021', 'CALLDATALOAD', uses=[offset], defines=['wdata'])
    region = ADDRESS
    if case in {'shifted_setter', 'multiply_setter'}:
        shift = b.stmt('0x2022', 'CONST', defines=['wshift'], literal=96)
        if case == 'multiply_setter':
            power = b.stmt('0x2026', 'CONST', defines=['wpower'], literal=1 << 96)
            value = b.stmt('0x2023', 'MUL', uses=[value, power], defines=['wshifted'])
        else:
            value = b.stmt('0x2023', 'SHL', uses=[shift, value], defines=['wshifted'])
        region = ADDRESS << 96
    elif case == 'packed_neighbor':
        region = WORD ^ ADDRESS
        shift = b.stmt('0x2024', 'CONST', defines=['wshift'], literal=160)
        value = b.stmt('0x2025', 'SHL', uses=[shift, value], defines=['wshifted'])
    elif case == 'partial_field':
        region = 255
    active = b.stmt('0x2030', 'CONST', defines=['wactive'], literal=region)
    new = b.stmt('0x2031', 'AND', uses=[value, active], defines=['wnew'])
    if case == 'or_unknown_storage':
        kept = old
    else:
        inverse = b.stmt('0x2032', 'CONST', defines=['winverse'], literal=WORD ^ region)
        kept = b.stmt('0x2033', 'AND', uses=[old, inverse], defines=['wkept'])
    merged = b.stmt('0x2034', 'OR', uses=[new, kept], defines=['wmerged'])
    if case == 'external_call_setter':
        wgas = b.stmt('0x2038', 'CONST', defines=['wgas'], literal=100000)
        b.stmt('0x2035', 'CALL', uses=[wgas, who, wz, wz, wz, wz, wz], defines=['wcall'])
    b.stmt('0x2036', 'SSTORE', uses=[key, merged])
    b.stmt('0x2037', 'STOP')
    if split_write:
        index = next(i for i, block in enumerate(b.blocks) if '0x2036' in block['statements'])
        block = b.blocks[index]
        at = max(1, len(block['statements']) // 2)
        continuation = {'id': '0x90', 'function': block['function'],
                        'successors': list(block['successors']), 'statements': block['statements'][at:]}
        block['statements'] = block['statements'][:at]
        block['successors'] = ['0x90']
        b.blocks.insert(index + 1, continuation)
    if rename:
        replacements = {'withdraw': 'entry_a', 'update': 'entry_b'}
        b.functions = [(replacements.get(n, n), selector) for n, selector in b.functions]
        for block in b.blocks:
            block['function'] = replacements.get(block['function'], block['function'])
    return b.emit(directory)
