"""Generate bounded alternative ABI encodings without changing decoded arguments.

The caller supplies a complete static head and one bytes/string tail. Moving the
tail and inserting unused gap words is a general way to falsify checks that read
a payload at an absolute calldata offset. Execution and a protocol effect oracle
are still required; generating encodings alone does not establish a vulnerability.
"""
from __future__ import annotations


def dynamic_calldata(selector: str, head: list[bytes], dynamic_index: int,
                     payload: bytes, gap_words: tuple[int, ...] = ()) -> str:
    if len(bytes.fromhex(selector.removeprefix("0x"))) != 4:
        raise ValueError("selector must be four bytes")
    if not 0 <= dynamic_index < len(head) or any(len(word) != 32 for word in head):
        raise ValueError("one static head word per argument is required")
    words = list(head)
    words[dynamic_index] = ((len(words) + len(gap_words)) * 32).to_bytes(32, "big")
    gap = b"".join(value.to_bytes(32, "big") for value in gap_words)
    tail = len(payload).to_bytes(32, "big") + payload + bytes((-len(payload)) % 32)
    return "0x" + selector.removeprefix("0x") + (b"".join(words) + gap + tail).hex()


def encoding_variants(selector: str, head: list[bytes], dynamic_index: int, payload: bytes,
                      decoy: int) -> dict[str, str]:
    """Canonical, one-word-gap and two-word-gap requests; the decoded arguments agree."""
    return {"canonical": dynamic_calldata(selector, head, dynamic_index, payload),
            "one_gap": dynamic_calldata(selector, head, dynamic_index, payload, (decoy,)),
            "two_gaps": dynamic_calldata(selector, head, dynamic_index, payload, (decoy, decoy))}
