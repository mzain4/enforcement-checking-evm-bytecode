"""CALLCODE is a result-bearing call, but not a direct external Ether payment."""
from pathlib import Path
import tempfile
import unittest

from implementation.enforcement_next.analyze import analyse_facts
from implementation.enforcement_next.controls import FactsBuilder


class CallcodeDirectPaymentTests(unittest.TestCase):
    def analyze(self, opcodes):
        with tempfile.TemporaryDirectory() as directory:
            b = FactsBuilder()
            b.function("__function_selector__", "0x00000000").block("0x1", [])
            b.stmt("0x2", "STOP")
            b.function("entry", "0x11111111").block("0x10", [])
            for sid, var, value in [
                ("0x11", "gas", 100000), ("0x12", "to", 0x123456789),
                ("0x13", "value", 7), ("0x14", "zero", 0),
            ]:
                b.stmt(sid, "CONST", defines=[var], literal=value)
            for index, opcode in enumerate(opcodes):
                b.stmt(hex(0x20 + index), opcode,
                       uses=["gas", "to", "value", "zero", "zero", "zero", "zero"],
                       defines=["result" + str(index)])
            b.stmt("0x40", "STOP")
            return analyse_facts(b.emit(Path(directory)))["properties"]

    def test_callcode_without_external_transfer_is_not_a_withdrawal(self):
        self.assertEqual(self.analyze(["CALLCODE"])["105"]["status"], "negative")

    def test_real_value_call_is_still_a_withdrawal(self):
        self.assertEqual(self.analyze(["CALL"])["105"]["status"], "positive")

    def test_callcode_keeps_call_result_obligation(self):
        self.assertEqual(self.analyze(["CALLCODE"])["104"]["status"], "positive")

    def test_later_call_is_not_hidden_by_callcode(self):
        result = self.analyze(["CALLCODE", "CALL"])["105"]
        self.assertEqual(result["status"], "positive")
        self.assertEqual(result["obligations"], 1)


if __name__ == "__main__":
    unittest.main()
