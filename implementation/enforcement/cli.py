"""Run a recorded, explicitly scoped enforcement analysis on one frozen fact set."""
from pathlib import Path
import argparse
import hashlib
import json
import sys
import traceback
from .facts import Facts
from .engine import Engine


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--facts',required=True,type=Path)
    parser.add_argument('--policy',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--wall-seconds',type=float,default=30)
    parser.add_argument('--max-states',type=int)
    parser.add_argument('--max-block-visits',type=int)
    parser.add_argument('--solver-ms',type=int)
    args=parser.parse_args();args.output.parent.mkdir(parents=True,exist_ok=True)
    policy=json.loads(args.policy.read_text(encoding='utf-8-sig'))
    if any(key in policy for key in ['gold','label','expected_status','vulnerable']):raise ValueError('Evaluation labels are not detector inputs')
    config={'wall_seconds':args.wall_seconds}
    for key,value in [('max_states',args.max_states),('max_block_visits',args.max_block_visits),('solver_timeout_ms',args.solver_ms)]:
        if value is not None:config[key]=value
    try:
        facts=Facts(args.facts)
        engine=Engine(facts,policy,config).run()
        result=engine.check()
    except Exception as error:
        result={'status':'analysis_error','error':str(error),'traceback':traceback.format_exc(),'benchmark_metrics':None}
    result.update(policy_sha256=hashlib.sha256(args.policy.read_bytes()).hexdigest(),
                  implementation_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')},
                  python=sys.version,facts_directory=str(args.facts.resolve()))
    args.output.write_text(json.dumps(result,indent=2),encoding='utf8')
    print(json.dumps({'output':str(args.output),'status':result.get('status','completed'),
                      'obligations':[(row['obligation'],row['status']) for row in result.get('obligations',[])],
                      'unknown_paths':len(result.get('unknown_paths',[])),'seconds':result.get('elapsed_seconds')}),flush=True)
    return 1 if result.get('status')=='analysis_error' else 0


if __name__=='__main__':raise SystemExit(main())
