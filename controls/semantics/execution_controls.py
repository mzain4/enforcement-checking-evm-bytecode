"""Fresh initialized SWC104 and EIP7702 controls; reuse pinned compiled bytes."""
from pathlib import Path
import hashlib
import json
import sys
import unittest

from eth_account import Account
from eth_abi import encode
from eth_utils import keccak
from eth_tester import EthereumTester, PyEVMBackend

from callcode_evm import push, deploy, invoke, GAS_PRICE

HERE = Path(__file__).resolve().parent
OUT = HERE.parents[1] / "runs/semantic-controls"
OUT.mkdir(parents=True, exist_ok=True)
ROOT = HERE.parents[1]


class Assembly:
    def __init__(self):
        self.code = bytearray()
        self.labels = {}
        self.patches = []

    def add(self, data):
        self.code.extend(data)

    def jump(self, label, conditional=False):
        self.patches.append((len(self.code) + 1, label))
        self.add(b"\x61\x00\x00" + (b"\x57" if conditional else b"\x56"))

    def label(self, label):
        self.labels[label] = len(self.code)
        self.add(b"\x5b")

    def finish(self):
        for at, label in self.patches:
            self.code[at:at + 2] = self.labels[label].to_bytes(2, "big")
        return bytes(self.code)


def value_call(address, value):
    return (push(0) * 4 + push(value) + push(int(address, 16), 20)
            + push(100_000) + b"\xf1")


def failure_event(reject):
    backend = PyEVMBackend()
    chain = EthereumTester(backend=backend)
    target = deploy(chain, bytes.fromhex("60006000fd"))
    recipient = chain.get_accounts()[2]
    asm = Assembly()
    asm.add(value_call(target, 0))
    if reject:
        asm.add(b"\x15")
        asm.jump("bad", conditional=True)
    else:
        asm.jump("success", conditional=True)
        asm.add(push(0) + push(0) + b"\xa0")
        asm.jump("join")
        asm.label("success")
        asm.jump("join")
        asm.label("join")
    asm.add(value_call(recipient, 7))
    asm.add(b"\x15")
    asm.jump("bad", conditional=True)
    asm.add(b"\x00")
    asm.label("bad")
    asm.add(bytes.fromhex("60006000fd"))
    runtime = asm.finish()
    caller = deploy(chain, runtime, 100)
    before = [chain.get_balance(a) for a in [caller, recipient, target]]
    receipt = invoke(chain, caller)
    after = [chain.get_balance(a) for a in [caller, recipient, target]]
    return {
        "response_to_first_failure": "revert" if reject else "event_then_continue",
        "transaction_status": receipt["status"], "log_count": len(receipt["logs"]),
        "caller_delta": after[0] - before[0], "recipient_delta": after[1] - before[1],
        "failed_call_target_delta": after[2] - before[2],
        "runtime_hex": runtime.hex(), "runtime_sha256": hashlib.sha256(runtime).hexdigest(),
        "failing_target_runtime": "60006000fd",
        "vm_class": backend.chain.get_vm().__class__.__name__,
        "interpretation": "a distinct event need not block later payment; no CGT label is created",
    }


def tx(chain, sender, target, signature, args=(), types=()):
    data = keccak(text=signature)[:4] + encode(types, args)
    return chain.get_transaction_receipt(chain.send_transaction({
        "from": sender, "to": target, "gas": 800_000,
        "gas_price": GAS_PRICE, "data": "0x" + data.hex(),
    }))


def read_uint(chain, sender, target, signature):
    return int(chain.call({"from": sender, "to": target,
                          "data": "0x" + keccak(text=signature)[:4].hex()}), 16)


def origin_account():
    backend = PyEVMBackend()
    chain = EthereumTester(backend=backend)
    owner, actor = chain.get_accounts()[:2]
    compiled = (ROOT / "controls/evm/compiled/modern-plain/compiler-output.json")
    payload = json.loads(compiled.read_text(encoding="utf-8"))
    contracts = next(v for v in payload["contracts"].values() if "OriginGate" in v)
    runtimes = {}
    addresses = {}
    for name in ["OriginGate", "Forwarder"]:
        code = contracts[name]["evm"]["bytecode"]["object"]
        receipt = chain.get_transaction_receipt(chain.send_transaction({
            "from": owner, "data": "0x" + code, "gas": 2_000_000,
            "gas_price": GAS_PRICE,
        }))
        assert receipt["status"] == 1
        addresses[name] = receipt["contract_address"]
        actual = bytes.fromhex(chain.get_code(addresses[name]).removeprefix("0x"))
        expected = bytes.fromhex(contracts[name]["evm"]["deployedBytecode"]["object"])
        assert actual == expected
        runtimes[name] = hashlib.sha256(actual).hexdigest()
    probe, forwarder = addresses["OriginGate"], addresses["Forwarder"]
    direct = tx(chain, actor, probe, "enter()")
    indirect = tx(chain, actor, forwarder, "run(address)", (probe,), ("address",))
    authorization = Account.sign_authorization({
        "chainId": backend.chain.chain_id, "address": forwarder,
        "nonce": chain.get_nonce(actor),
    }, backend.account_keys[1])
    fee = chain.get_block_by_number("latest")["base_fee_per_gas"]
    signed = Account.sign_transaction({
        "type": 4, "chainId": backend.chain.chain_id, "nonce": chain.get_nonce(owner),
        "to": owner, "gas": 150000, "maxFeePerGas": fee * 2 + 1_000_000_000,
        "maxPriorityFeePerGas": 1_000_000_000, "value": 0, "data": "0x",
        "authorizationList": [authorization],
    }, backend.account_keys[0])
    setup = chain.get_transaction_receipt(
        chain.send_raw_transaction("0x" + signed.raw_transaction.hex()))
    delegated = tx(chain, actor, actor, "run(address)", (probe,), ("address",))
    return {
        "direct_status": direct["status"], "ordinary_forwarder_status": indirect["status"],
        "authorization_status": setup["status"], "delegated_self_call_status": delegated["status"],
        "probe_count": read_uint(chain, owner, probe, "count()"),
        "observed_caller_code_bytes": read_uint(chain, owner, probe, "lastCodeSize()"),
        "delegation_code": chain.get_code(actor), "compiled_file": str(compiled),
        "compiled_file_sha256": hashlib.sha256(compiled.read_bytes()).hexdigest(),
        "runtime_sha256": runtimes, "vm_class": backend.chain.get_vm().__class__.__name__,
        "scope": "fresh type4 authorization and execution using already compiled controls",
    }


class ExecutionControls(unittest.TestCase):
    events = []
    accounts = []

    def test_failure_event_can_precede_later_payment(self):
        for repeat in range(3):
            row = failure_event(False)
            self.events.append(dict(repetition=repeat + 1, **row))
            self.assertEqual((row["transaction_status"], row["log_count"],
                              row["caller_delta"], row["recipient_delta"],
                              row["failed_call_target_delta"]), (1, 1, -7, 7, 0))

    def test_rejection_prevents_later_payment(self):
        for repeat in range(3):
            row = failure_event(True)
            self.events.append(dict(repetition=repeat + 1, **row))
            self.assertEqual((row["transaction_status"], row["log_count"],
                              row["caller_delta"], row["recipient_delta"]), (0, 0, 0, 0))

    def test_delegated_account_passes_origin_equality_while_code_executes(self):
        for repeat in range(3):
            row = origin_account()
            self.accounts.append(dict(repetition=repeat + 1, **row))
            self.assertEqual(tuple(row[k] for k in [
                "direct_status", "ordinary_forwarder_status", "authorization_status",
                "delegated_self_call_status", "probe_count", "observed_caller_code_bytes",
            ]), (1, 0, 1, 1, 2, 23))
            self.assertTrue(row["delegation_code"].startswith("0xef0100"))


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ExecutionControls))
    (OUT / "execution-results.json").write_text(json.dumps({
        "passed": result.wasSuccessful(), "tests_run": result.testsRun,
        "failure_event_executions": ExecutionControls.events,
        "eip7702_executions": ExecutionControls.accounts,
        "scope": "authored initialized execution controls; no independent benchmark claims",
    }, indent=2) + "\n", encoding="utf-8")
    sys.exit(0 if result.wasSuccessful() else 1)
