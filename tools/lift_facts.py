"""Run Gigahorse on fixed runtime inputs and retain every preparation outcome."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RELATIONS = ['contract.tac', 'TAC_Op.csv', 'TAC_Variable_Value.csv', 'TAC_Use.csv', 'TAC_Def.csv',
             'PublicFunction.csv', 'HighLevelFunctionName.csv', 'FormalArgs.csv']


def main():
    sys.path.insert(0, str(ROOT))
    from artifact_data import ensure_data
    ensure_data()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--gigahorse', type=Path, required=True)
    p.add_argument('--python', default=sys.executable)
    p.add_argument('--view', choices=['released', 'withdrawal'], required=True)
    p.add_argument('--output', required=True)
    args = p.parse_args()
    if os.name == 'nt':
        p.error('Run the compatible Gigahorse frontend from Linux or WSL')
    gig = args.gigahorse.resolve()
    if not (gig / 'gigahorse.py').is_file():
        p.error('Gigahorse toolchain directory with gigahorse.py required')
    out = (ROOT / 'runs' / args.output).resolve()
    if not out.is_relative_to((ROOT / 'runs').resolve()) or out.exists():
        p.error('Choose a new directory beneath runs/')
    (out / 'inputs').mkdir(parents=True)
    data = ROOT / 'experiments' / ('dataset' if args.view == 'released' else 'withdrawal-view-v02')
    items = [json.loads(s) for s in (data / 'inputs.jsonl').read_text().splitlines() if s.strip()]
    inputs = []
    unavailable = []
    for item in items:
        source = data / item['runtime_path'] if item.get('runtime_path') else None
        if source is None or not source.is_file():
            unavailable.append({'runtime_sha256': item['runtime_sha256'], 'status': 'runtime_unavailable'})
            continue
        raw = bytes.fromhex(''.join(source.read_text().split()).removeprefix('0x'))
        assert hashlib.sha256(raw).hexdigest() == item['runtime_sha256']
        target = out / 'inputs' / (item['runtime_sha256'] + '.hex')
        shutil.copy2(source, target)
        inputs.append(target)
    identities = {str(f.relative_to(gig)): hashlib.sha256(f.read_bytes()).hexdigest()
                  for f in [gig / 'gigahorse.py', gig / 'logic/decompiler_input_opcodes.dl', *sorted((gig / 'src').glob('*.py'))] if f.is_file()}
    command = [args.python, str(gig / 'gigahorse.py'), '--reuse_datalog_bin', '-j', '4', '-T', '180',
               '-w', str(out / 'work'), '-r', str(out / 'frontend-results.json'),
               '-C', str(gig / 'clients/visualizeout.py'), *map(str, inputs)]
    environment = dict(os.environ, OMP_NUM_THREADS='1', PYTHONDONTWRITEBYTECODE='1')
    if (gig / 'souffle-addon').is_dir():
        environment['LD_LIBRARY_PATH'] = str(gig / 'souffle-addon') + os.pathsep + environment.get('LD_LIBRARY_PATH', '')
    with (out / 'frontend-console.txt').open('wb') as log:
        proc = subprocess.run(command, cwd=out, stdout=log, stderr=subprocess.STDOUT, env=environment)
    records = list(unavailable)
    for inp in inputs:
        possible = [out / 'work' / inp.stem / 'out', out / 'work' / inp.name / 'out']
        facts = next((d for d in possible if (d / 'contract.tac').is_file()), None)
        if facts is None:
            records.append({'runtime_sha256': inp.stem, 'status': 'no_visualized_facts'})
            continue
        dest = out / 'facts' / inp.stem
        dest.mkdir(parents=True)
        exported = []
        for relation in RELATIONS:
            if (facts / relation).is_file():
                shutil.copy2(facts / relation, dest / relation)
                exported.append(relation)
        shutil.copy2(inp, dest / 'bytecode.hex')
        records.append({'runtime_sha256': inp.stem, 'status': 'facts_exported', 'relations': exported})
    (out / 'preparation.json').write_text(json.dumps({'command': command, 'frontend_sha256': identities,
        'frontend_returncode': proc.returncode, 'inputs': len(items), 'records': records, 'labels_read': False}, indent=2))
    print('Retained preparation outcomes for', len(records), 'inputs under', out)


if __name__ == '__main__':
    main()
