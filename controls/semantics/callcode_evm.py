"""Initialized, offline EVM evidence for direct CALL/CALLCODE value semantics."""
from pathlib import Path
import hashlib
import json
import sys
import unittest

from eth_tester import EthereumTester, PyEVMBackend

HERE = Path(__file__).resolve().parent
OUT = HERE.parents[1] / "runs/semantic-controls"
OUT.mkdir(parents=True, exist_ok=True)
GAS_PRICE = 2_000_000_000


def push(value, width=None):
    if width is None:
        width = max(1, (value.bit_length() + 7) // 8)
    return bytes([0x5f + width]) + value.to_bytes(width, "big")


def init(runtime):
    return b"\x61" + len(runtime).to_bytes(2, "big") + bytes.fromhex(
        "61000f60003961"
    ) + len(runtime).to_bytes(2, "big") + bytes.fromhex("6000f3") + runtime


def deploy(chain, runtime, value=0):
    receipt = chain.get_transaction_receipt(chain.send_transaction({
        "from": chain.get_accounts()[0], "data": "0x" + init(runtime).hex(),
        "gas": 1_500_000, "gas_price": GAS_PRICE, "value": value,
    }))
    assert receipt["status"] == 1, receipt
    address = receipt["contract_address"]
    assert bytes.fromhex(chain.get_code(address).removeprefix("0x")) == runtime
    return address


def invoke(chain, address):
    return chain.get_transaction_receipt(chain.send_transaction({
        "from": chain.get_accounts()[1], "to": address, "gas": 800_000,
        "gas_price": GAS_PRICE, "value": 0,
    }))


def caller_runtime(target, opcode, value=7):
    # out-size/out-offset/in-size/in-offset/value/to/gas; returned context occupies
    # memory 0..95, and success occupies memory 96..127.
    runtime = push(96) + push(0) + push(0) + push(0) + push(value)
    runtime += push(int(target, 16), 20) + push(100_000) + bytes([opcode])
    runtime += push(96) + b"\x52"
    for slot in range(4):
        runtime += push(slot * 32) + b"\x51" + push(slot) + b"\x55"
    return runtime + push(128) + push(0) + b"\xf3"


def scenario(opcode, balance=100):
    backend = PyEVMBackend()
    chain = EthereumTester(backend=backend)
    # Recorder returns ADDRESS, CALLER and CALLVALUE and performs no outgoing call.
    recorder = bytes.fromhex("30600052336020523460405260606000f3")
    target = deploy(chain, recorder)
    runtime = caller_runtime(target, opcode)
    caller = deploy(chain, runtime, balance)
    before = {a: chain.get_balance(a) for a in [caller, target]}
    receipt = invoke(chain, caller)
    after = {a: chain.get_balance(a) for a in [caller, target]}
    observed = [int(chain.get_storage_at(caller, hex(n)), 16) for n in range(4)]
    return {
        "opcode": "CALL" if opcode == 0xf1 else "CALLCODE",
        "funded_balance": balance, "value_operand": 7,
        "transaction_status": receipt["status"], "inner_success": observed[3],
        "caller_contract": caller, "code_target": target,
        "observed_address": hex(observed[0]), "observed_caller": hex(observed[1]),
        "observed_callvalue": observed[2],
        "balance_delta": {"caller_contract": after[caller] - before[caller],
                          "code_target": after[target] - before[target]},
        "runtime_hex": runtime.hex(),
        "runtime_sha256": hashlib.sha256(runtime).hexdigest(),
        "target_runtime_hex": recorder.hex(),
        "vm_class": backend.chain.get_vm().__class__.__name__,
        "outgoing_transfers_in_target": 0,
    }


class CallcodeSemantics(unittest.TestCase):
    records = []

    def test_call_transfers_value_to_code_target(self):
        row = scenario(0xf1)
        self.records.append(row)
        self.assertEqual((row["transaction_status"], row["inner_success"]), (1, 1))
        self.assertEqual(row["balance_delta"], {"caller_contract": -7, "code_target": 7})
        self.assertEqual(int(row["observed_address"], 16), int(row["code_target"], 16))
        self.assertEqual(int(row["observed_caller"], 16), int(row["caller_contract"], 16))
        self.assertEqual(row["observed_callvalue"], 7)

    def test_callcode_passes_value_context_without_external_transfer(self):
        row = scenario(0xf2)
        self.records.append(row)
        self.assertEqual((row["transaction_status"], row["inner_success"]), (1, 1))
        self.assertEqual(row["balance_delta"], {"caller_contract": 0, "code_target": 0})
        self.assertEqual(int(row["observed_address"], 16), int(row["caller_contract"], 16))
        self.assertEqual(int(row["observed_caller"], 16), int(row["caller_contract"], 16))
        self.assertEqual(row["observed_callvalue"], 7)

    def test_callcode_still_checks_available_balance(self):
        row = scenario(0xf2, balance=5)
        self.records.append(row)
        self.assertEqual((row["transaction_status"], row["inner_success"]), (1, 0))
        self.assertEqual(row["balance_delta"], {"caller_contract": 0, "code_target": 0})


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(CallcodeSemantics)
    )
    payload = {"passed": result.wasSuccessful(), "tests_run": result.testsRun,
               "records": CallcodeSemantics.records,
               "scope": "authored offline Prague EVM controls; not CGT labels or independent validation"}
    (OUT / "callcode-evm-results.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    sys.exit(0 if result.wasSuccessful() else 1)
