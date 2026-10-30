"""Isolate field precision on existing authored fixtures; not a native-tool comparison."""
from pathlib import Path
import hashlib
import inspect
import json
import sys
import tempfile
import importlib.util
W = Path(__file__).resolve().parents[1]
CORRECTION = W
def import_file(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2))

sys.path.insert(0,str(W))
from implementation.enforcement_state import analyze as model


def main():
    fixtures=import_file(CORRECTION/'support/controls.py','field_fixture_factory')
    original=model.credential_candidates
    source=inspect.getsource(original)
    needle="controlled = bits(facts, op.uses[1])[0]"
    assert source.count(needle)==1
    coarsened=source.replace(needle,needle+"\n                controlled = WORD if controlled else 0")
    outcomes=[]
    with tempfile.TemporaryDirectory(prefix='field-control-') as temp:
        for name,(expected,_) in fixtures.CASES.items():
            facts=fixtures.build(Path(temp)/name,name)
            sensitive=model.analyse_facts(facts)['properties']['105']['status']
            off=model.analyse_facts(facts,credential_integrity=False)['properties']['105']['status']
            try:
                exec(compile(coarsened,'<word-mask-ablation>','exec'),model.__dict__)
                whole=model.analyse_facts(facts)['properties']['105']['status']
            finally:
                model.credential_candidates=original
            assert sensitive==expected,(name,sensitive,expected)
            outcomes.append({'authored_fixture':name,'declared_development_expectation':expected,
                             'credential_off':off,'field_sensitive':sensitive,'word_mask_coarsened':whole})
    algebra=[]
    for protected,written in [(15,240),(240,15),(15,3),(240,48)]:
        changed=False
        checked=0
        for old in range(256):
            for value in range(256):
                updated=(old & (255 ^ written)) | (value & written)
                differs=(updated & protected)!=(old & protected)
                changed |= differs
                checked+=1
                if not (protected & written):
                    assert not differs
        assert changed==bool(protected & written)
        algebra.append({'protected_mask':hex(protected),'write_mask':hex(written),
                        'assignments_checked':checked,'protected_bits_can_change':changed})
    result={'passed':True,'fixture_rows':outcomes,'reused_authored_fixtures':len(outcomes),
            'changed_rows':[r for r in outcomes if r['field_sensitive']!=r['word_mask_coarsened']],
            'word_ablation_source_sha256':hashlib.sha256(coarsened.encode()).hexdigest(),
            'algebra_cases':algebra,'toy_assignments_checked':sum(r['assignments_checked'] for r in algebra),
            'scope':'existing authored fixtures plus8-bit exhaustive update algebra; not independent natural data, native Ethainter or whole-checker soundness'}
    save(W/'runs/controls/field-precision-results.json',result)
    print(json.dumps({k:result[k] for k in ['passed','reused_authored_fixtures','changed_rows','toy_assignments_checked','scope']},indent=2))


if __name__=='__main__':
    main()
