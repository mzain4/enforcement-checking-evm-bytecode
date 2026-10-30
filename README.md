# Dependency-Aware Enforcement Checker (DAEC)

Experiment code for **Dependency-Aware Security Enforcement Checking for Ethereum Bytecode**.

DAEC evaluates call-result handling (SWC-104), withdrawal authorization (SWC-105) and transaction-origin
roles (SWC-115) over Gigahorse facts. Credential checks track public control of guarding storage fields
and caller-keyed membership entries. Detection does not read benchmark labels.

## Authors

1. Muhammad Zain Ul Abidin — [mzain.mz4@gmail.com](mailto:mzain.mz4@gmail.com)
2. Imtiaz Hussain — [imtiaz.hussain@skt.umt.edu.pk](mailto:imtiaz.hussain@skt.umt.edu.pk)
3. Intakhab Alam — [intakhab.alam@skt.umt.edu.pk](mailto:intakhab.alam@skt.umt.edu.pk)
4. Syed Shakeel ur Rehman — [shakeelrizvi94@yahoo.com](mailto:shakeelrizvi94@yahoo.com)

Department of Computer Science, University of Management and Technology,
Lahore (Sialkot Campus), Pakistan.

## Requirements and controls

Use Python **3.11 or newer**. Static checks, scoring and authored controls use the standard library.

```bash
python tools/check_source.py
python reproduce.py controls
python check_results.py
```

These commands check source identities, 41 rule regressions, six native-export tests, 25 authored/
metamorphic programs, four keyed-slot cases, the field-mask ablation and 17 saved-result assertions.
They do not require the large benchmark snapshot or validate benchmark predictions independently.

Run the full checker on your own prepared Gigahorse facts:

```bash
python run_experiments.py worker --facts /path/to/facts --arm full --code .
```

## Benchmark experiments

The CGT-derived inputs, fixed labels, prepared facts and recorded runs are kept separately from Git.
Full benchmark verification requires a raw snapshot matching `data/EVIDENCE_SHA256.json`. Supply that
snapshot with `--source`; this source release does not supply a hosted download URL for it.

```bash
python tools/prepare_data.py --source /path/to/raw-evidence --verify
python reproduce.py verify
python replay.py --profile common --workers 4
python reproduce.py results

# Seven internal arms plus two full-method repeats on both populations.
python reproduce.py experiments --profile all --workers 4 --name census-1
```

`verify` checks evidence identities, 18 corrected-run configurations, original/corrected status agreement,
110 method/view scores, raw-record correspondence, reference consensus and paired family intervals.
`results` regenerates ten evaluation views into a fresh directory beneath `runs/` and compares them
with fixed `results/tables.json`. Missing evidence raises an explicit setup error.

New runs retain configuration, code/input hashes, raw outcomes and comparisons. Use a new name or
`--resume` with an identical configuration. Failures, timeouts, unsupported inputs and unknowns remain
in the population. References are joined only by scoring. The internal arms are presence rules, local
dependencies, DAEC, and ablations of origin-role, guard/ledger, call-result and keyed-membership reasoning.

See [reproduction commands](docs/REPRODUCING.md), [data requirements](docs/DATA.md),
[method and scoring](docs/METHOD.md), [third-party notices](THIRD_PARTY.md) and [citation](CITATION.cff).

## Execution controls and native comparators

Concrete EVM controls use the pinned dependencies in `requirements-evm.txt` in a separate Python3.11
virtual environment. They execute saved compiled programs on fresh in-memory chains:

```bash
python controls/evm/check.py
python controls/identity/replay.py
python controls/semantics/callcode_evm.py
python controls/semantics/execution_controls.py
```

Native Mythril, Slither and Securify runs require their own environments. Their exact settings,
compiler preparation and commands are documented in `docs/REPRODUCING.md`.

## Layout

```text
implementation/      detector and fact reader
baselines/           field-integrity baseline for mapping controls
controls/            authored and initialized execution controls
tests/               rule and export regression tests
results/             compact scores and diagnostics
support/             fixed scorer, toolchain records and third-party notices
tools/               data setup, compiler/fact preparation and integrity checks
docs/                experimental protocol, data provenance and method scope
```

Project code is MIT-licensed; third-party material retains its original notices. Independent human
credential assessment is absent. Family overlap, development exposure and coverage-sensitive scoring
remain part of the interpretation of the saved results.
