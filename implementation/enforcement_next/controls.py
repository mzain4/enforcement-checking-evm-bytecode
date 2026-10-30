"""Author synthetic Gigahorse facts for rule controls (development/regression tests only).

Each control is a hand-written micro-program in the same shape the decompiler emits: one dispatcher function,
one public function, plain block identifiers. The controls are not CGT samples and are never scored; they
exist so that every rule's positive, negative and unknown meaning can be checked before the public cases.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Tuple


class FactsBuilder:
    def __init__(self):
        self.functions: List[Tuple[str, str]] = []          # (name, selector or '')
        self.blocks: List[Dict[str, object]] = []           # ordered
        self.ops: List[Tuple[str, str]] = []                # statement id, op
        self.uses: List[Tuple[str, str, int]] = []
        self.defs: List[Tuple[str, str, int]] = []
        self.literals: Dict[str, int | None] = {}
        self._current: Dict[str, object] | None = None
        self._function: str | None = None

    def function(self, name: str, public_selector: str = ''):
        self.functions.append((name, public_selector))
        self._function = name
        return self

    def block(self, block_id: str, successors: List[str] | None = None):
        block = {'id': block_id, 'function': self._function,
                 'successors': list(successors or []), 'statements': []}
        self.blocks.append(block)
        self._current = block
        return self

    def successors(self, *successors: str):
        assert self._current is not None
        self._current['successors'] = list(successors)
        return self

    def stmt(self, statement_id: str, op: str, uses: List[str] | None = None,
             defines: List[str] | None = None, literal: int | None = None):
        self.ops.append((statement_id, op))
        self.literals[statement_id] = literal
        for index, var in enumerate(uses or []):
            self.uses.append((statement_id, var, index))
        for index, var in enumerate(defines or []):
            self.defs.append((statement_id, var, index))
        assert self._current is not None
        self._current['statements'].append(statement_id)
        return statement_id

    def emit(self, directory: Path):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        ops = dict(self.ops)
        lines: List[str] = []
        for name, _ in self.functions:
            lines.append('function %s() public {' % name)
            for block in self.blocks:
                if block['function'] != name:
                    continue
                lines.append('    Begin block %s' % block['id'])
                lines.append('    prev=[], succ=[%s]' % ', '.join(block['successors']))
                lines.append('    =================================')
                for statement_id in block['statements']:
                    arguments = [var for statement, var, _ in self.uses if statement == statement_id]
                    defined = [var for statement, var, _ in self.defs if statement == statement_id]
                    target = ''
                    if defined:
                        literal = self.literals.get(statement_id)
                        shown = defined[0] + ('(%s)' % hex(literal) if literal is not None else '')
                        target = '%s = ' % shown
                    suffix = (' ' + ', '.join(arguments)) if arguments else ''
                    lines.append('    %s: %s%s%s ' % (statement_id, target, ops[statement_id], suffix))
            lines.append('}')
            lines.append('')
        (directory / 'contract.tac').write_text('\n'.join(lines), encoding='utf8')
        (directory / 'TAC_Op.csv').write_text(''.join('%s\t%s\n' % row for row in self.ops), encoding='utf8')
        (directory / 'TAC_Use.csv').write_text(''.join('%s\t%s\t%d\n' % row for row in self.uses), encoding='utf8')
        (directory / 'TAC_Def.csv').write_text(''.join('%s\t%s\t%d\n' % row for row in self.defs), encoding='utf8')
        (directory / 'PublicFunction.csv').write_text(
            ''.join('%s\t%s\n' % (self._entry_block(name), selector)
                    for name, selector in self.functions if selector), encoding='utf8')
        (directory / 'HighLevelFunctionName.csv').write_text(
            ''.join('%s\t%s\n' % (self._entry_block(name), name) for name, _ in self.functions),
            encoding='utf8')
        (directory / 'FormalArgs.csv').write_text('', encoding='utf8')
        (directory / 'TAC_Variable_Value.csv').write_text('', encoding='utf8')
        return directory

    def _entry_block(self, name: str) -> str:
        for block in self.blocks:
            if block['function'] == name:
                return block['id']
        raise KeyError(name)
