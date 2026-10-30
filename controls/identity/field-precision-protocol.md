# Field-mask ablation

Run `python controls/check_fields.py` from the repository root. The experiment uses 13 authored
fixtures and compares three configurations:

- Credential-integrity checking disabled.
- Field-sensitive credential-integrity checking.
- A word-mask ablation that expands the final controllable-write mask to the whole word whenever any
  controlled bit is established.

Guard reasoning, runtime inputs and fixture expectations remain fixed. The ablation replaces the
mask calculation in memory and restores the field-sensitive function after each fixture. Results
are written to `runs/controls/field-precision-results.json`.

The same command exhaustively checks 8-bit update algebra for four `(protected, write)` mask pairs:
`(0x0f, 0xf0)`, `(0xf0, 0x0f)`, `(0x0f, 0x03)` and `(0xf0, 0x30)`. For each pair, it evaluates all
65,536 old-value/input-value assignments, totaling 262,144 assignments. Disjoint masks must preserve
every protected bit; overlapping masks must permit at least one protected bit to change. This checks
the small-width update algebra separately from the detector fixtures.
