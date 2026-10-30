# Reproducing the method and experiments

Run commands from the repository root. Python 3.11+ is sufficient for static analysis, saved-output
verification, scoring, authored controls and bootstrap calculations. Use separate environments for
native tools and EVM execution; their dependency sets are incompatible with one shared environment.

Dataset-independent checks are `python reproduce.py controls`, `python check_results.py` and
`python tools/check_source.py`. For full benchmark commands, supply the separately stored raw evidence
with `python tools/prepare_data.py --source /path/to/raw-evidence --verify`. A source clone alone does
not include prepared facts or recorded benchmark outputs. No hosted snapshot URL is provided here.

## 1. Integrity and recorded results

```bash
python reproduce.py verify
```

`verify.py` checks `MANIFEST.json`, independently counts confusion cells, checks every exported status
against its per-input record, checks references against provider consensus, and checks prepared facts
against runtime SHA-256. `verify_bootstrap.py` repeats 2,000 paired source-family resamples over 265
connected groups. `check_results.py` checks substantive comparative assertions. `verify_correction.py` checks the
18 corrected-run code/input identities and agreement with the preserved original records. This path does not execute native analyzers, the frontend or EVM scenarios.

Bootstrap verification uses an absolute floating-point tolerance of 1e-12 and reports the maximum difference.

```bash
python reproduce.py results
```

This regenerates saved-output evaluations, machine-readable scores and predictions
in a fresh `runs/results-*/` directory, comparing the metrics with the fixed `results/` records. The fixed
evidence is preserved. Securify records are decoded from the fixed native request archive: final run
status overrides stale output, nested verdicts are scoped to the target contract and warnings retain
uncertainty.

## 2. Execute the detector

```bash
python replay.py --profile common --workers 4
python replay.py --profile census --workers 4

python run_experiments.py run --view released --profile common --arm full --output full-1 --workers 4
python score_run.py full-1

python run_experiments.py run --view withdrawal --arm full --output source-full-1 --workers 4
python score_run.py source-full-1
```

The two replay commands compare a new full-method execution with recorded decisions. The run/score
commands retain fresh raw records. Detection workers reject attempts to open label/prediction files;
the score command joins references afterwards. Each prepared runtime is checked against its input hash.
The outer process cap is 60 seconds. Missing facts produce `unsupported`, not a negative.

Available arms: `presence`, `local`, `full`, `no-origin`, `no-guard`, `no-callresult`, `no-membership`.
`no-membership` retains field integrity and isolates the keyed-credential extension.

```bash
python reproduce.py experiments --profile common --name cohort-1 --workers 4
python reproduce.py experiments --profile all --name census-1 --workers 4
```

Each matrix runs seven arms plus two extra full-method repeats on the released population and the
62-input source population. `common` restricts only the released population to the fixed 267 runtimes.
Every run is exported and compared against recorded per-cell decisions. Output summaries are
`runs/cohort-1-summary.json` and `runs/census-1-summary.json`. CPU and operating-system differences can
affect timing and timeout boundaries; a mismatch is reported and retained rather than suppressed.

## 3. Authored and EVM controls

```bash
python reproduce.py controls
```

The 41 rule tests, six native-export tests, 25 authored/metamorphic programs and four keyed-slot cases
need no extra packages. The mask ablation also checks 262,144 small-width assignments. Controls are
evaluated separately from the CGT benchmark.

For concrete executions, create a Python 3.11 environment and install the pinned EVM packages:

```bash
python -m venv .venv-evm
# Activate .venv-evm for your shell, then:
python -m pip install -r requirements-evm.txt
python controls/evm/check.py
python controls/identity/replay.py
```

Expected summaries are five compiler configurations / 50 credential scenarios / 15 account outcomes
with no problems, and 32 gas scenarios / 96 executions / no differences. Each command starts a fresh,
in-memory PyEVM chain. The commands execute saved compiled programs; they do not invoke the compiler.
Compiler inputs and outputs are included beside the controls.

To compile the five configurations again, set `SOLC_084` and `SOLC_0838` to the corresponding compiler
executables, set `RECOMPILE_CONTROLS=1`, then run `python controls/evm/check.py`. New outputs go to
`runs/evm-controls/`; the committed control programs are preserved.

## 4. Native comparators

The following commands execute the native comparators. Install each tool in a separate environment
using the dependency sets under `support/toolchain/`. Recorded native outputs are checked by
`python reproduce.py verify`.

### Mythril 0.24.8

Use a dedicated Python 3.11 environment with Mythril 0.24.8. Put its `myth` executable on PATH or set
`MYTHRIL_EXE` to its full path. Run the driver with the standard-library Python environment:

```bash
python run_mythril.py run --population full --profile common --transactions 2 --output mythril-1 --workers 4
python score_native.py mythril-1
python run_mythril.py run --population withdrawal-v02 --transactions 2 --output mythril-source-1 --workers 4
python score_native.py mythril-source-1
```

The configured modules are EtherThief, UncheckedRetval and TxOrigin; transaction count 2, depth 64,
execution cap 60 seconds, solver cap 5,000 ms, outer cap 90 seconds, and no on-chain data. A no-issue
outcome near 57 seconds is unknown under the recorded timing heuristic, not a proof of search exhaustion.

### Slither 0.11.6

Use a separate Python environment with Slither 0.11.6. Set `SLITHER_PYTHON` to that interpreter and
`SOLC_DIR` to a directory containing the required `solc-VERSION` executables (`.exe` on Windows).
`python tools/install_compilers.py` downloads the versions named by the fixed correspondence records,
checks the official binary hashes and writes them under `tools/solc/`.

```bash
python run_slither.py run --view released --profile common --output slither-1 --workers 4
python score_native.py slither-1
python run_slither.py run --view withdrawal-v02 --profile all --output slither-source-1 --workers 4
python score_native.py slither-source-1
```

The worker verifies executable correspondence after the declared metadata normalization and scopes
results to the selected contract and inheritance. Detectors: unchecked-lowlevel, unchecked-send,
arbitrary-send-eth and tx-origin. The process cap is 60 seconds. References are not sent to the worker.

### Securify 2, commit 1913dfe

Use Linux and the pinned native source archive in `support/native-tools/`; its upstream README contains
the installation procedure. It requires its compatible Python environment, Souffle **1.6.2**, Graphviz
and the matching libfunctors library path. The parent driver uses Python 3.11+, while `--python` selects
the isolated native interpreter. The supplied requests already contain verified compiler ASTs.

```bash
python run_securify.py --view withdrawal --python /path/to/securify-env/bin/python --output securify-1
python score_native.py securify-1
python run_securify.py --view released --python /path/to/securify-env/bin/python --output securify-released-1
python score_native.py securify-released-1
```

The 44-case compatible withdrawal view and ten released diagnostic inputs are fixed before analysis.
The wrapper uses the unmodified AST/CFG API, three configured patterns and the Souffle interpreter under
a 180-second cap. Run status and native verdicts are retained for scoring.

## 5. Bytecode preparation

Committed facts are the fixed inputs for the measured detector runs. Bytecode, source/compiler
correspondence, fact preparation failures and frontend identities are retained under `experiments/`
and `support/`. The frontend source archive includes the recorded normalization material.

```bash
python tools/lift_facts.py --gigahorse /path/to/gigahorse-toolchain --python /path/to/frontend-env/bin/python --view released --output lifting-1
```

This starts a separate Gigahorse run using the original input bytes and recorded invocation pattern.
It preserves each input's preparation outcome and actual frontend hashes. A different frontend build
must be validated before replacing the fixed facts. The preparation time cap (180 seconds) and input
availability are distinct from the detector's 60-second cap.

## File identities

`METHOD_SHA256.json` identifies the 18 implementation modules. `MANIFEST.json`, `data/ASSETS.json` and
`data/EVIDENCE_SHA256.json` provide file-integrity checks. See [CONTRIBUTING.md](../CONTRIBUTING.md) for
changes to measured inputs or detector rules.

Additional initialized semantic controls (in the pinned EVM environment):

```bash
python controls/semantics/callcode_evm.py
python controls/semantics/execution_controls.py
```

These execute CALL/CALLCODE balance contexts, failure-event behavior and EIP-7702 delegation. They write only beneath ignored runs/semantic-controls/.
