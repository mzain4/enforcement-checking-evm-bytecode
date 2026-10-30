"""Replay saved compiled controls on a fresh local EVM; no compiler is re-executed."""
import json
from eth_abi import encode
from eth_tester import EthereumTester, PyEVMBackend
from eth_utils import keccak
from pathlib import Path
import hashlib
W = Path(__file__).resolve().parent
def read(path): return json.loads(path.read_text(encoding='utf8'))
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    expected = read(W / 'identity-results.json')
    if sha(W / 'IdentityProbe.sol') != expected['source_sha256']:
        raise ValueError('Control source changed')
    compiled = read(W / 'identity-compiler-output.json')
    code = compiled['contracts']['IdentityProbe.sol']['IdentityProbe']['evm']['bytecode']['object']
    chain = EthereumTester(PyEVMBackend())
    sender = chain.get_accounts()[0]
    receipt = chain.get_transaction_receipt(chain.send_transaction({'from':sender,'gas':6000000,'data':'0x'+code}))
    assert receipt['status']==1
    target = receipt['contract_address']
    differences = []
    executions = 0
    for scenario in expected['records']:
        for previous in scenario['observations']:
            snapshot = chain.take_snapshot()
            data = keccak(text='probe(uint256,uint256,bool)')[:4] + encode(['uint256','uint256','bool'],
                    [scenario['forwarded_gas'],scenario['words'],scenario['enforce']])
            result = chain.get_transaction_receipt(chain.send_transaction({'from':sender,'to':target,'gas':2000000,'data':'0x'+data.hex()}))
            def get(signature):
                return int(chain.call({'from':sender,'to':target,'gas':100000,'data':'0x'+keccak(text=signature)[:4].hex()}),16)
            current = {'outer_status':result['status'],'stored_success':bool(get('lastSuccess()')),
                       'stored_copy':hex(get('lastCopy()'))}
            if current != previous:
                differences.append({'scenario':scenario['words'],
                                    'gas':scenario['forwarded_gas'],'expected':previous,'observed':current})
            executions += 1
            chain.revert_to_snapshot(snapshot)
    report = {'passed':not differences,'executions':executions,'scenarios':len(expected['records']),
              'differences':differences,'scope':'fresh EVM execution of saved compiled artifact; compiler not rerun'}
    print(json.dumps(report,indent=2))
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
