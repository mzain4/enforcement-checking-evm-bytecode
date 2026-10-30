"""Run the paper's verification, controls, or fresh internal experiment matrix."""
from pathlib import Path
import argparse
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
ARMS = ['presence', 'local', 'no-origin', 'no-guard', 'no-callresult', 'no-membership', 'full']


def run(*arguments):
    subprocess.run([sys.executable, '-X', 'utf8', '-B', *arguments], cwd=ROOT, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['verify', 'controls', 'results', 'experiments'])
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--profile', choices=['common', 'all'], default='common')
    parser.add_argument('--name', default='reproduction', help='Fresh experiment prefix beneath runs/')
    parser.add_argument('--resume', action='store_true')
    args = parser.parse_args()
    if args.command == 'verify':
        run('verify.py')
        run('verify_bootstrap.py')
        run('check_results.py')
    elif args.command == 'controls':
        run('-m', 'unittest', 'discover', '-s', 'tests', '-v')
        run('test_corrections.py', '-v')
        run('replay.py', '--profile', 'controls')
        run('controls/check_mapping.py')
        run('controls/check_fields.py')
    elif args.command == 'results':
        run('regenerate_results.py')
    else:
        reports = []
        for view in ['released', 'withdrawal']:
            profile = args.profile if view == 'released' else 'all'
            for arm, suffix in [(a, a) for a in ARMS] + [('full', 'full-repeat-2'), ('full', 'full-repeat-3')]:
                name = f'{args.name}-{view}-{suffix}'
                command = ['run_experiments.py', 'run', '--view', view, '--profile', profile,
                           '--arm', arm, '--output', name, '--workers', str(args.workers)]
                if args.resume:
                    command += ['--resume']
                run(*command)
                run('score_run.py', name)
                reports.append(json.loads((ROOT / 'runs' / name / 'comparison.json').read_text()))
        output = ROOT / 'runs' / (args.name + '-summary.json')
        output.write_text(json.dumps({'passed': all(r['passed'] for r in reports), 'runs': reports}, indent=2))
        print('All fresh internal runs reproduce the recorded decisions:', output)


if __name__ == '__main__':
    main()
