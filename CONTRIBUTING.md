# Working with measured results

Keep `implementation/` independent of labels, provider identities and source names. Read labels only
during export/scoring. Preserve failures, timeouts and unknown decisions; never replace them with
negative predictions or remove them from the evaluation population.

Keep recorded runs and fixed references intact. New executions belong under `runs/` with their own
configuration, input/code identities and process records. Rule changes require matched arm/repeat,
regression, semantic-control and scoring checks before updating research claims. Do not tune references,
thresholds or selection to improve reported values. Preserve family overlap and development exposure.

After intentional source or documentation changes, use `python tools/update_manifest.py` to record
the new tracked-file identities. Do not refresh a manifest merely to silence an unexplained data or
method mismatch. A measured method change requires a new corresponding experiment record.

Project code is MIT-licensed. Retain all third-party licenses and source notices.

Canonical evidence is stored locally as ordinary files and ignored by Git. Its identities are in data/EVIDENCE_SHA256.json, separately from the source/documentation manifest. Preserve prior evidence when adding a correction; do not update hashes to conceal an unexplained difference. The repository contains experiments only, without manuscript or paper-building tools.
