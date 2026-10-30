"""Execute explicitly initialized credential and EIP-7702 scenarios on a local Prague EVM."""
from pathlib import Path
import hashlib
import json
import subprocess
import os

import eth
import eth_account
import eth_tester
from eth_account import Account
from eth_abi import encode
from eth_tester import EthereumTester, PyEVMBackend
from eth_utils import keccak

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = HERE / 'CredentialControls.sol'
SOLC_OLD = Path(os.environ.get('SOLC_084', ROOT / 'tools/solc/solc-0.8.4'))
SOLC_NEW = Path(os.environ.get('SOLC_0838', ROOT / 'tools/solc/solc-0.8.38'))
CONFIGS = [('legacy-plain', SOLC_OLD, False, False, 'berlin'),
           ('legacy-opt', SOLC_OLD, True, False, 'berlin'),
           ('modern-plain', SOLC_NEW, False, False, 'prague'),
           ('modern-opt', SOLC_NEW, True, False, 'prague'),
           ('modern-ir', SOLC_NEW, True, True, 'prague')]
CASES = {'OpenCaller': True, 'GuardedCaller': False, 'NeighborField': False, 'ShiftedField': True,
         'OpenParameter': True, 'Initialized': False, 'TwoCredentials': False,
         'NoSetter': False, 'PartialField': False, 'ExternalSetter': True}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def transact(chain, sender, target, signature='', args=(), types=(), value=0):
    data = keccak(text=signature)[:4] + encode(types, args) if signature else b''
    tx = chain.send_transaction({'from': sender, 'to': target, 'gas': 2_000_000,
                                 'value': value, 'data': '0x' + data.hex()})
    return chain.get_transaction_receipt(tx)


def deploy(chain, sender, contracts, name):
    tx = chain.send_transaction({'from': sender, 'gas': 6_000_000,
                                 'data': '0x' + contracts[name]['evm']['bytecode']['object']})
    receipt = chain.get_transaction_receipt(tx)
    assert receipt['status'] == 1, (name, receipt)
    return receipt['contract_address']


def uint(chain, sender, target, signature):
    return int(chain.call({'from': sender, 'to': target, 'gas': 1_000_000,
                          'data': '0x' + keccak(text=signature)[:4].hex()}), 16)


def main():
    output = ROOT / 'runs/evm-controls'
    output.mkdir(parents=True, exist_ok=True)
    problems = []
    results = []
    for name, solc, optimized, via_ir, target in CONFIGS:
        settings = {'optimizer': {'enabled': optimized, 'runs': 200}, 'evmVersion': target,
                    'outputSelection': {'*': {'*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object']}}}
        if solc == SOLC_NEW:
            settings['viaIR'] = via_ir
        request = {'language': 'Solidity', 'sources': {'Controls.sol': {'content': SOURCE.read_text()}},
                   'settings': settings}
        if os.environ.get('RECOMPILE_CONTROLS') == '1':
            process = subprocess.run([str(solc.resolve()), '--standard-json'], input=json.dumps(request),
                                     capture_output=True, text=True, encoding='utf8', timeout=60)
            compiled = json.loads(process.stdout)
            errors = [e for e in compiled.get('errors', []) if e['severity'] == 'error']
            if errors or process.returncode:
                problems.append({'config': name, 'errors': errors, 'stderr': process.stderr})
                continue
        else:
            compiled = json.loads((HERE / 'compiled' / name / 'compiler-output.json').read_text())
            saved_request = json.loads((HERE / 'compiled' / name / 'compiler-input.json').read_text())
            assert saved_request == request, 'Control source/settings differ from compiled input'
        build = output / name
        build.mkdir(exist_ok=True)
        (build / 'compiler-input.json').write_text(json.dumps(request, indent=2), encoding='utf8')
        (build / 'compiler-output.json').write_text(json.dumps(compiled), encoding='utf8')
        contracts = compiled['contracts']['Controls.sol']
        backend = PyEVMBackend()
        chain = EthereumTester(backend=backend)
        owner, actor = chain.get_accounts()[:2]
        cases = {}
        for contract, expected in CASES.items():
            address = deploy(chain, owner, contracts, contract)
            transact(chain, owner, address, value=100)
            runtime = bytes.fromhex(chain.get_code(address).removeprefix('0x'))
            (build / (contract + '.hex')).write_text(runtime.hex(), encoding='utf8')
            signature, types, args = ('claim(address)', ('address',), (actor,)) if contract in {
                'OpenParameter', 'ExternalSetter'} else ('claim()', (), ())
            claim = transact(chain, actor, address, signature, args, types)
            before = chain.get_balance(address)
            receipt = transact(chain, actor, address, 'withdraw()')
            lost = before - chain.get_balance(address)
            actual = bool(receipt['status'] == 1 and lost == 100)
            if actual != expected:
                problems.append({'config': name, 'case': contract, 'expected_payout': expected, 'lost': lost})
            cases[contract] = {'claim_status': claim['status'], 'withdraw_status': receipt['status'],
                'contract_value_delta': -lost, 'actor_can_take_funded_value': actual,
                'runtime_sha256': sha(runtime), 'runtime_bytes': len(runtime)}
        probe = deploy(chain, owner, contracts, 'OriginGate')
        forwarder = deploy(chain, owner, contracts, 'Forwarder')
        direct = transact(chain, actor, probe, 'enter()')
        indirect = transact(chain, actor, forwarder, 'run(address)', (probe,), ('address',))
        actor_key = backend.account_keys[1]
        owner_key = backend.account_keys[0]
        authorization = Account.sign_authorization({'chainId': backend.chain.chain_id,
            'address': forwarder, 'nonce': chain.get_nonce(actor)}, actor_key)
        fee = chain.get_block_by_number('latest')['base_fee_per_gas']
        signed = Account.sign_transaction({'type': 4, 'chainId': backend.chain.chain_id,
            'nonce': chain.get_nonce(owner), 'to': owner, 'gas': 150000,
            'maxFeePerGas': fee * 2 + 1_000_000_000, 'maxPriorityFeePerGas': 1_000_000_000,
            'value': 0, 'data': '0x', 'authorizationList': [authorization]}, owner_key)
        tx = chain.send_raw_transaction('0x' + signed.raw_transaction.hex())
        setup = chain.get_transaction_receipt(tx)
        delegated = transact(chain, actor, actor, 'run(address)', (probe,), ('address',))
        account = {'direct_status': direct['status'], 'ordinary_forwarder_status': indirect['status'],
            'authorization_status': setup['status'], 'delegated_self_call_status': delegated['status'],
            'probe_count': uint(chain, owner, probe, 'count()'),
            'observed_caller_code_bytes': uint(chain, owner, probe, 'lastCodeSize()'),
            'delegation_code': chain.get_code(actor)}
        if (account['direct_status'], account['ordinary_forwarder_status'], account['authorization_status'],
            account['delegated_self_call_status'], account['probe_count'], account['observed_caller_code_bytes']) != (1, 0, 1, 1, 2, 23):
            problems.append({'config': name, 'eip7702': account})
        results.append({'config': name, 'compiler_sha256': (sha(solc.read_bytes()) if os.environ.get('RECOMPILE_CONTROLS') == '1' else next(r['compiler_sha256'] for r in json.loads((HERE/'compiled-controls.json').read_text())['configurations'] if r['config'] == name)), 'settings': settings,
                        'vm': type(backend.chain.get_vm()).__name__, 'cases': cases, 'account_context': account})
    report = {'schema': 'credential-compiled-controls/v1', 'source_sha256': sha(SOURCE.read_bytes()),
        'toolchain': {'pyevm': eth.__version__, 'eth_tester': eth_tester.__version__,
                      'eth_account': eth_account.__version__},
        'initial_state': 'owner is deployer, distinct actor; each vault starts funded with 100 wei',
        'interpretation': 'Authored initialized scenarios and correlated compiler builds, not independent benchmark vulnerabilities.',
        'configurations': results, 'problems': problems}
    (output / 'compiled-controls.json').write_text(json.dumps(report, indent=2), encoding='utf8')
    print(json.dumps({'configurations': len(results), 'credential_scenarios': sum(len(r['cases']) for r in results),
                      'account_scenarios': len(results) * 3, 'problems': problems}, indent=2))
    return bool(problems)


if __name__ == '__main__':
    raise SystemExit(main())
