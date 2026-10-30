"""Conservative, concrete ABI dynamic-array binding.

This module is an isolated variant.  It does not participate in symbolic Engine
execution.  A binding is only produced when the ABI head, relative offset, array
length, and every element range are concrete and validated.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

MAX_ELEMENTS = 4
WORD_SIZE = 32
COIN_ARRAY_TYPE = "(address,uint256)[]"


@dataclass(frozen=True)
class ArrayBinding:
    base: int
    length: int
    element_size: int
    array_type: str
    binding_id: str


@dataclass(frozen=True)
class BindingResult:
    status: Literal["bound", "unknown", "rejected"]
    binding: ArrayBinding | None = None
    reason: str = ""


def _unknown(reason: str) -> BindingResult:
    return BindingResult("unknown", reason=reason)


def _rejected(reason: str) -> BindingResult:
    return BindingResult("rejected", reason=reason)


def bind_dynamic_array(
    calldata: bytes,
    *,
    head_offset: int | None,
    relative_offset: int | None,
    element_size: int | None,
    array_type: str | None,
    binding_id: str | None,
    expected_binding_id: str,
    expected_type: str = COIN_ARRAY_TYPE,
    max_elements: int = MAX_ELEMENTS,
) -> BindingResult:
    """Bind one validated ABI dynamic array, or return a conservative result.

    ``relative_offset`` is relative to the ABI argument block (byte zero is
    immediately after the four-byte selector).  The supplied head and offset
    must agree with the calldata; an unrelated dynamic argument therefore
    cannot be silently reused.
    """
    if not isinstance(calldata, (bytes, bytearray, memoryview)):
        return _unknown("calldata is not concrete")
    if any(value is None for value in
           (head_offset, relative_offset, element_size, array_type, binding_id)):
        return _unknown("dynamic head metadata is unbound")
    if expected_binding_id != binding_id:
        return _unknown("binding identity is unbound")
    if array_type != expected_type:
        return _unknown("array type is unrelated")
    if max_elements != MAX_ELEMENTS or max_elements <= 0:
        return _rejected("maximum element limit is not the explicit limit")
    if not isinstance(head_offset, int) or not isinstance(relative_offset, int):
        return _unknown("head or relative offset is symbolic")
    if not isinstance(element_size, int) or element_size <= 0:
        return _rejected("invalid element size")
    if head_offset < 4 or head_offset % WORD_SIZE != 4:
        return _rejected("dynamic head is not an ABI head")
    if head_offset + WORD_SIZE > len(calldata):
        return _rejected("dynamic head exceeds calldata")
    if relative_offset < WORD_SIZE or relative_offset % WORD_SIZE:
        return _rejected("relative offset is malformed")
    encoded_offset = int.from_bytes(bytes(calldata[head_offset:head_offset + WORD_SIZE]), "big")
    if encoded_offset != relative_offset:
        return _unknown("head does not validate the supplied relative offset")
    argument_block = 4
    base = argument_block + relative_offset
    if base < argument_block or base + WORD_SIZE > len(calldata):
        return _rejected("array length word exceeds calldata")
    length = int.from_bytes(bytes(calldata[base:base + WORD_SIZE]), "big")
    if length > max_elements:
        return _rejected("array length exceeds MAX_ELEMENTS")
    if element_size > (1 << 63) or length > ((1 << 63) - 1) // element_size:
        return _rejected("array size overflows")
    end = base + WORD_SIZE + length * element_size
    if end < base or end > len(calldata):
        return _rejected("array elements exceed calldata")
    for index in range(length):
        start = base + WORD_SIZE + index * element_size
        if start < base or start + element_size > len(calldata):
            return _rejected("element exceeds calldata")
    return BindingResult(
        "bound",
        ArrayBinding(base, length, element_size, array_type, binding_id),
    )


def bind_fixed_array(
    calldata: bytes,
    *,
    base: int | None,
    length: int | None,
    element_size: int | None,
    array_type: str = "(address,uint256)[2]",
    binding_id: str = "coin-loop",
    max_elements: int = MAX_ELEMENTS,
) -> BindingResult:
    """Bounded control adapter for a statically sized array."""
    if any(value is None for value in (base, length, element_size)):
        return _unknown("fixed-array metadata is unbound")
    if not all(isinstance(value, int) for value in (base, length, element_size)):
        return _unknown("fixed-array metadata is symbolic")
    if length != 2 or length > max_elements or length < 0:
        return _rejected("fixed control is not [2] within MAX_ELEMENTS")
    if element_size <= 0 or base < 0 or base + length * element_size > len(calldata):
        return _rejected("fixed-array elements exceed calldata")
    return BindingResult("bound", ArrayBinding(base, length, element_size, array_type, binding_id))
