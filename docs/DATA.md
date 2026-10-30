# Data and provenance

The benchmark inputs derive from Consolidated Ground Truth (CGT), revision
`f8cd72cf7fbbfebc809c454667eee271706a4b2b`, by Monika di Angelo and Gernot Salzer.

`data/ASSETS.json` describes the ordinary benchmark files; `data/EVIDENCE_SHA256.json` pins their SHA-256 values. Run
`python tools/prepare_data.py` after supplying a raw snapshot with `--source PATH` to check the following local directories:

- `experiments/dataset/`: 1,431 released runtimes, fixed assessment records, source inputs and prepared facts.
- `experiments/common-cohort.json`: 267 source/compiler-corresponding runtimes, 449 assessed cells.
- `experiments/withdrawal-view-v02/`: 62 source-derived family/target cases; compilation failures retained.
- `experiments/source-correspondence/`: compiler attempts, identities and executable-prefix checks.
- `experiments/securify-preparation/protocol.json`: the fixed compatible native request inventory.
- `experiments/*/runs/`: per-runtime decisions and evidence for each named method/ablation/repeat.
- `results/views/`: labelled score exports for ten explicitly separated populations.

The runtime census has 333 positive, 2,348 negative and 19 disputed cells across the three selected SWC
categories. The matched cohort has 56 positive and 393 negative cells. The 62 source cases have 57
positive and five negative assessments; the compatible 44-case subset has 41 positive and three negative.
Unassessed properties are not negatives. Family fingerprints retain overlap across views.

Source-derived inputs represent compiler-specific executions of supplied source. Source-family
fingerprints record overlap with released inputs. Original assessment disagreements remain in the data.

CGT licensing is retained in `support/CGT-LICENSE.txt`, with its upstream README and metadata. Source
headers and third-party software licenses remain in place. The fixed scorer is in
`support/frozen_scorer.py`; its reference policy is independent of the detector.

Corrected internal records are under experiments/callcode-correction/. They retain the 18 completed arms/repeats after the CALLCODE direct-payment correction. Original records remain in their original directories; native comparators and references are unchanged. Verification compares every original/corrected property status and pins the corrected code.

The large data/evidence directories are ignored by Git and are not included in a source clone. The local working copy retains them. Full recorded-result reproduction requires a separately supplied matching raw snapshot; this repository provides its identity manifest but no hosted download URL. Dataset-independent controls and code execution on user-supplied facts remain available from the source clone.
