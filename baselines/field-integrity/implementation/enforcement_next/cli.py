"""Command line for the next-generation enforcement rules."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyze import DEFAULT_FLAGS, FLAG_NAMES, analyse_facts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--facts', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    for name in FLAG_NAMES:
        parser.add_argument('--no-' + name.replace('_', '-'), action='store_true',
                            help='disable the %s refinement' % name)
    args = parser.parse_args(argv)
    flags = dict(DEFAULT_FLAGS)
    for name in FLAG_NAMES:
        if getattr(args, 'no_' + name):
            flags[name] = False
    result = analyse_facts(args.facts, flags)
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding='utf8')
    else:
        print(text, end='')
    return 0 if result.get('status') == 'ok' else 1


if __name__ == '__main__':
    raise SystemExit(main())
