# Method and scoring

The input is a runtime and Gigahorse operation, definition, use, constant, public-entry and control-flow
facts. The three property checks return positive, negative or unknown; execution records also retain
unsupported preparation, timeouts and errors.

- SWC-104: connect a low-level call's success value to rejecting or differentiated failure handling.
- SWC-105: require supported identity/limit protection or consumption of the paid caller's credit.
- SWC-115: distinguish authorization use of transaction origin from incidental uses.
- Credential integrity: connect guarding fields to public writes with complete control of the relevant
  bits, distinguishing neighboring packed updates and partial writes.
- Keyed membership: recognize a supported word-encoded mapping hash, relate caller-keyed guards and
  writes to the same base, and separate constant keys, unrelated bases and guarded writers.

Checks evaluate supported data and control-flow relationships in the supplied facts. Per-runtime
records retain the property decisions, supporting obligations and unresolved dependencies. A negative
decision concerns the configured checks on that input, rather than a whole-contract safety guarantee.

Labels enter only during export/scoring. Positive-reference abstentions count as false negatives;
negative-reference abstentions count as neither FP nor TN. Decisive coverage is reported. The alternative
penalty F1 charges negative-reference abstentions as a sensitivity, not as confirmed false alarms.
Disputed assessments remain unresolved. Source-only, injected and released views are not pooled as
independent contracts.

`results/tables.json` contains the scores and sensitivity calculations for each assessment view.

CALLCODE remains subject to call-result checks, but its value operand is not a direct transfer to the code address. The correction is covered by regression and initialized EVM controls; all 18 corrected internal jobs retain the original property statuses and scores. Differentiated failure events do not prove adequate application recovery. Caller/origin equality does not exclude delegated account-code execution under EIP-7702.
