"""Verify, run and score the pinned CGT EVM component benchmark.

Data/labels are frozen separately from run outputs. Raw execution does not invent
a mapping from SmartAxe's CCV classes to generic SWC properties.
"""
from __future__ import annotations
import argparse
from collections import Counter
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = next((p for p in HERE.parents if (p/'scripts/baseline_case.py').is_file()), None)
STATUSES = {'positive','negative','unknown','unsupported','error','timeout'}

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def read_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding='utf8').splitlines() if line.strip()]

def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n',encoding='utf8')

def write_rows(path,rows):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(''.join(json.dumps(r,sort_keys=True)+'\n' for r in rows),encoding='utf8')

def cases(profile):
    profiles=json.loads((HERE/'profiles.json').read_text())
    wanted=set(profiles[profile]['case_ids'])
    return [r for r in read_jsonl(HERE/'labels.jsonl') if r['case_id'] in wanted]

def score_records(labels,predictions,method):
    by_id={}
    for row in predictions:
        key=row.get('case_id')
        if key in by_id:raise ValueError('Duplicate prediction: '+str(key))
        if row.get('status') not in STATUSES:raise ValueError('Invalid prediction status for '+str(key))
        by_id[key]=row
    gold={r['case_id']:r for r in labels}
    if set(gold)!=set(by_id):
        raise ValueError(f'Prediction population mismatch: missing={sorted(set(gold)-set(by_id))[:4]}, extra={sorted(set(by_id)-set(gold))[:4]}')
    def calculate(rows):
        c=Counter();statuses=Counter()
        for r in rows:
            status=by_id[r['case_id']]['status'];statuses[status]+=1
            if r['vulnerable'] is None:c['unresolved_reference']+=1;continue
            c['known_positive' if r['vulnerable'] else 'known_negative']+=1
            if status=='positive':c['tp' if r['vulnerable'] else 'fp']+=1
            elif status=='negative':c['fn' if r['vulnerable'] else 'tn']+=1
            elif r['vulnerable']:c['fn']+=1;c['abstained_positive']+=1
            else:c['abstained_negative']+=1
        tp,fp,fn=c['tp'],c['fp'],c['fn']
        p=tp/(tp+fp) if tp+fp else None
        r=tp/(tp+fn) if tp+fn else None
        f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None
        return {'counts':{k:c[k] for k in ('tp','fp','fn','tn','known_positive','known_negative','abstained_positive','abstained_negative','unresolved_reference')},
                'precision':p,'recall':r,'f1':f1,'prediction_statuses':dict(statuses),
                'decisive_coverage':sum(statuses[k] for k in ('positive','negative'))/len(rows) if rows else None}
    classes=sorted({r['swc'] for r in labels})
    by_class={swc:calculate([r for r in labels if r['swc']==swc]) for swc in classes}
    return {'schema':'published-cgt-score/v1','method':method,'unit':'(runtime, SWC property)',
            'cases':len(labels),'primary_end_to_end':calculate(labels),'by_swc':by_class,
            'macro_f1':sum((r['f1'] or 0) for r in by_class.values())/len(classes) if classes else None,
            'policy':'Unknown, unsupported, error and timeout predictions remain misses for known positives; negative abstentions are not certified safe. Reference disputes are reported separately.',
            'comparison_limit':'These scores are on CGT contract/property labels; SmartAxe published 79/14/9 scores use different labels and trace units.'}

def verify():
    manifest=json.loads((HERE/'manifest.json').read_text());problems=[]
    for name,digest in manifest['files'].items():
        path=HERE/name
        if not path.is_file() or sha(path)!=digest:problems.append('Changed or missing: '+name)
    inputs=read_jsonl(HERE/'inputs.jsonl');ids={r['input_id'] for r in inputs}
    if len(ids)!=len(inputs):problems.append('Duplicate input identities')
    for r in inputs:
        code=bytes.fromhex((HERE/r['runtime_path']).read_text().strip())
        if hashlib.sha256(code).hexdigest()!=r['runtime_sha256']:problems.append('Runtime identity mismatch: '+r['input_id'])
    labels=read_jsonl(HERE/'labels.jsonl')
    if len({r['case_id'] for r in labels})!=len(labels):problems.append('Duplicate scoring cells')
    if any(r['input_id'] not in ids for r in labels):problems.append('Label points outside input population')
    if any(r['vulnerable'] is not None and type(r['vulnerable']) is not bool for r in labels):problems.append('Invalid reference label')
    # Recompute the selected population and labels from the pinned original assessments.
    protocol=json.loads((HERE/'protocol.json').read_text())
    with (HERE/'upstream/consolidated.csv').open(encoding='utf-8-sig',newline='') as stream:
        upstream=list(csv.DictReader(stream,delimiter=';'))
    providers=set(protocol['selection']['providers']);swcs=set(protocol['selection']['swc'])
    expected={(r['fp_runtime'],r['swc']) for r in upstream if r['dataset'] in providers and r['swc'] in swcs and r['fp_runtime']}
    actual={(r['input_id'].removeprefix('CGT-'),r['swc']) for r in labels}
    if expected!=actual:problems.append('Selected population differs from upstream protocol')
    for r in labels:
        identity=r['input_id'].removeprefix('CGT-')
        values={u['property_holds'] for u in upstream if u['fp_runtime']==identity and u['swc']==r['swc']}
        expected_label=(next(iter(values))=='t') if len(values)==1 else None
        if expected_label is not r['vulnerable']:problems.append('Upstream label mismatch: '+r['case_id'])
    profiles=json.loads((HERE/'profiles.json').read_text())
    all_cases={r['case_id'] for r in labels}
    if set(profiles['full']['case_ids'])!=all_cases:problems.append('Full profile does not cover labels')
    return problems

def input_for_profile(profile):
    wanted={r['input_id'] for r in cases(profile)}
    return [r for r in read_jsonl(HERE/'inputs.jsonl') if r['input_id'] in wanted]

def extension_input_check(facts,output):
    sys.path.insert(0,str(ROOT))
    from implementation.enforcement.facts import Facts
    from implementation.enforcement.engine import Engine
    f=Facts(facts);rows=[]
    for selector in sorted(set(f.public.values()))[:3]:
        policy={'policy_id':'cgt_input_compatibility','selector':selector,
                'effects':['plain_call','value_call','log','storage_write']}
        result=Engine(f,policy,{'wall_seconds':3,'check_wall_seconds':2,'max_states':100,'max_block_visits':2,'solver_timeout_ms':250}).run().check()
        rows.append({'selector':selector,'statistics':result.get('statistics'),'unknown_paths':result.get('unknown_paths'),
                     'obligation_count':len(result.get('obligations',[]))})
    save(output,{'status':'input_compatibility_passed','facts':str(facts),'input_summary':f.summary(),
                 'exploration':rows,'score_prediction':None,
                 'scope':'Loader and bounded exploration smoke only. A property-compatible semantic policy and output adapter must be specified before SWC scoring.'})

def run_raw(args):
    if ROOT is None:raise ValueError('Project runtime not found; use --predictions with score for external tools.')
    output=args.output.resolve()
    if output==HERE or HERE in output.parents:raise ValueError('Run outputs must be outside the frozen dataset.')
    if output.exists() and any(output.iterdir()):raise ValueError('Use a new empty run directory.')
    output.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
    summary=[]
    for item in input_for_profile(args.profile):
        identity=item['runtime_sha256'];facts=HERE/'facts'/identity
        row={'input_id':item['input_id'],'runtime_sha256':identity,'method':args.method}
        target=output/identity;target.mkdir()
        if not (facts/'contract.tac').is_file():
            row.update(status='preprocessing_unavailable',score_prediction=None);summary.append(row);continue
        if args.method=='smartaxe':
            readiness=json.loads((HERE/'readiness.json').read_text())
            prepared=next((r for r in readiness['inputs'] if r['runtime_sha256']==identity),{})
            legacy=facts if args.parser_only else HERE/prepared.get('smartaxe_facts','smartaxe-inputs/'+identity+'/merged')
            if not args.parser_only and not (legacy/(identity+'.sol')).is_file():
                row.update(status='smartaxe_rendering_unavailable',score_prediction=None);summary.append(row);continue
            tool_input=target/'tool-inputs'
            shutil.copytree(legacy,tool_input)
            base=ROOT/'recovered/code-snapshot/smartAxe'
            command=[str(ROOT/'tools/runtime/python38/python.exe'),'-B',str(ROOT/'scripts/baseline_case.py'),
                     '--baseline',str(base),'--facts',str(tool_input),'--signatures',str(base/'gigahorse/gigahorse-toolchain'),
                     '--contract',identity,'--output',str(target/'raw.json')]
            if args.parser_only:command.append('--parser-only')
        else:
            tool_input=target/'tool-inputs'
            shutil.copytree(facts,tool_input)
            command=[sys.executable,'-B',str(Path(__file__).resolve()),'_extension','--facts',str(tool_input),'--output',str(target/'raw.json')]
        input_hashes={p.name:sha(p) for p in sorted(tool_input.iterdir()) if p.is_file()}
        row['input_facts_sha256']=hashlib.sha256(json.dumps(input_hashes,sort_keys=True).encode()).hexdigest()
        started=time.monotonic()
        try:
            proc=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True,timeout=args.timeout,encoding='utf8',errors='replace')
            (target/'stdout.txt').write_text(proc.stdout,encoding='utf8');(target/'stderr.txt').write_text(proc.stderr,encoding='utf8')
            raw=json.loads((target/'raw.json').read_text()) if (target/'raw.json').is_file() else {}
            row.update(status=raw.get('status','process_failed'),returncode=proc.returncode,score_prediction=None)
        except subprocess.TimeoutExpired:
            row.update(status='timeout',score_prediction=None)
        row.update(elapsed_seconds=round(time.monotonic()-started,3),raw_output=str((target/'raw.json').relative_to(output)))
        row['tool_input_unchanged']=input_hashes=={p.name:sha(p) for p in sorted(tool_input.iterdir()) if p.is_file()}
        summary.append(row);save(output/'execution.json',{'method':args.method,'profile':args.profile,'records':summary})
        print(identity[:12],row['status'],flush=True)
    record={'schema':'published-cgt-raw-run/v1','method':args.method,'parser_only':args.parser_only,'profile':args.profile,'records':summary,
            'dataset_manifest_sha256':sha(HERE/'manifest.json') if (HERE/'manifest.json').exists() else None,
            'tool_hashes':{str(p.relative_to(ROOT)).replace('\\','/'):sha(p) for p in [ROOT/'implementation/enforcement/engine.py',ROOT/'implementation/enforcement/facts.py',ROOT/'scripts/baseline_case.py']},
            'metrics':None,'reason':'Raw tool execution is not automatically equivalent to a per-SWC prediction. Keep task applicability and a validated property mapping explicit.'}
    save(output/'execution.json',record)
    return 1 if any(r['status'] in {'process_failed','error','failed'} for r in summary) else 0

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('verify');sub.add_parser('describe')
    for name in ('template','constant','score'):
        s=sub.add_parser(name);s.add_argument('--profile',choices=['full','quick','smoke'],default='full');s.add_argument('--output',type=Path,required=True)
        if name=='score':s.add_argument('--predictions',type=Path,required=True);s.add_argument('--method',required=True)
        if name=='constant':s.add_argument('--strategy',choices=['all-positive','all-negative'],default='all-positive')
    s=sub.add_parser('run-raw');s.add_argument('--method',choices=['smartaxe','extension'],required=True)
    s.add_argument('--profile',choices=['full','quick','smoke'],default='smoke');s.add_argument('--timeout',type=float,default=60)
    s.add_argument('--output',type=Path,required=True)
    s.add_argument('--parser-only',action='store_true',help='SmartAxe input parser compatibility check; not detector execution')
    s=sub.add_parser('_extension');s.add_argument('--facts',type=Path,required=True);s.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    if args.command=='verify':
        problems=verify();print(json.dumps({'problems':problems,'read_only':True},indent=2));return bool(problems)
    if args.command=='describe':print((HERE/'protocol.json').read_text());return 0
    if args.command=='_extension':extension_input_check(args.facts,args.output);return 0
    if args.command=='run-raw':return run_raw(args)
    destination=args.output.resolve()
    if destination==HERE or HERE in destination.parents:
        raise ValueError('Scoring/template outputs must be outside the frozen dataset.')
    if destination.exists():
        raise ValueError('Preserve existing output; choose a new result path.')
    selected=cases(args.profile)
    if args.command=='template':
        write_rows(args.output,[{'case_id':r['case_id'],'status':'unknown','evidence':[]} for r in selected]);return 0
    if args.command=='constant':
        status='positive' if args.strategy=='all-positive' else 'negative'
        predictions=[{'case_id':r['case_id'],'status':status} for r in selected]
        prediction_path=args.output.with_suffix('.predictions.jsonl')
        if prediction_path.exists():raise ValueError('Preserve existing prediction output; choose a new path.')
        write_rows(prediction_path,predictions)
        result=score_records(selected,predictions,args.strategy)
    else:result=score_records(selected,read_jsonl(args.predictions),args.method)
    result.update(profile=args.profile,labels_sha256=sha(HERE/'labels.jsonl'))
    save(args.output,result);print(json.dumps(result['primary_end_to_end'],indent=2));return 0

if __name__=='__main__':
    raise SystemExit(main())
