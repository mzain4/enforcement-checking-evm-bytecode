"""Use Securify 2's unmodified AST/CFG/analysis API on compiler-verified source."""
from pathlib import Path
import json
import sys
import time

from semantic_version import Version
from securify.solidity.solidity_cfg_compiler import compile_cfg
from securify.staticanalysis.static_analysis import analyze_cfg
from securify.analyses.analysis import AnalysisContext, AnalysisConfiguration
from securify.analyses.patterns.abstract_pattern import MatchSourceLocation, MatchComment
from securify.__main__ import get_list_of_patterns

request = json.loads(Path(sys.argv[1]).read_text())
ast = request['ast']
ast['source'] = request['source']
ast['_solc_version'] = Version(request['compiler_version'])
started = time.monotonic()
compiled = compile_cfg(ast)
static = analyze_cfg(compiled.cfg, use_interpreter=True)
context = AnalysisContext(config=AnalysisConfiguration(), source_code=request['source'],
                          ast=compiled.ast, cfg=compiled.cfg, static=static)
patterns = get_list_of_patterns(context=context, patterns=['UnhandledException', 'UnrestrictedEtherFlow', 'TxOrigin'])
records = []
for pattern in patterns:
    matches = []
    for match in pattern.find_matches():
        locations = [dict(start=s.start, end=s.end, line=s.line, contract=s.contract)
                     for s in match.find_info(MatchSourceLocation)]
        if locations and not any(s['contract'] in request['target_scope'] for s in locations):
            continue
        comments = [s.comment for s in match.find_info(MatchComment)]
        matches.append({'type': match.type.name, 'locations': locations, 'comments': comments})
    records.append({'pattern': pattern.__class__.__name__, 'name': pattern.name, 'matches': matches})
result = {'status': 'actual_analysis_completed', 'source_sha256': request['source_sha256'],
          'compiler_version': request['compiler_version'], 'target_scope': request['target_scope'],
          'backend': 'unmodified Souffle 1.6.2 interpreter', 'elapsed_seconds': time.monotonic() - started,
          'patterns': records, 'facts_out': static.facts_out, 'backend_stdout': static.stdout, 'backend_stderr': static.stderr}
Path(sys.argv[2]).write_text(json.dumps(result, indent=2, sort_keys=True))
print(json.dumps({'status': result['status'], 'patterns': records}), flush=True)
