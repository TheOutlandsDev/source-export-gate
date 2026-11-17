# Usage

Use absolute owner-controlled private paths. Directories700 and regular single-link
files600 are required for candidates and private controls. Output destinations must
be new and outside the candidate. Limits:128 files,2,000,000 bytes/file,8,000,000
bytes per batch and the existing lexical path/depth policy. Content is UTF8/noNUL.

Selection JSON has format `outlands-source-export-intake-selection-v1`, a known
family label and sorted unique files. Each row declares path,artifact_kind and
synthetic_fixture. Example for invented content:

```json
{"format":"outlands-source-export-intake-selection-v1","family":"java-python-kits","files":[{"path":"Example.java","artifact_kind":"source","synthetic_fixture":true},{"path":"example.py","artifact_kind":"source","synthetic_fixture":true}]}
```

```sh
python3 -I -B build_review_intake.py --candidate ABS_CANDIDATE --selection ABS_SELECTION --output ABS_NEW_INTAKE
python3 -I -B verify_review_intake.py --candidate ABS_CANDIDATE --selection ABS_SELECTION --intake ABS_INTAKE
```

The v0.11 builder writes seven metadata files: CLAIM.json, proposal.json,
review-draft.json, paired CHECKLIST.md/TXT, evidence-bindings.json, and a v2
INTAKE-COMPLETE.json written last. Six human review fields stay pending.
Successful pending HOLD exits1;
input refusal/partial uncertainty exits2. Capture and reread counters are separate.

The verifier validates the exact versioned member set, completion hashes, pending
review and binding schema before opening the candidate root. New v2 packets bind
the exact raw selection SHA-256, the gate and builder source SHA-256 hashes used
at creation, selected declarations, proposal bytes and review-draft bytes. An
otherwise equivalent selection with changed whitespace is STALE. A gate/builder
policy hash mismatch is STALE before candidate access. Valid current bindings
report MATCHED only after all selected-file and final packet checks pass. No
verifier implementation hash is recorded: it was not a creation policy.

Require v2 bindings explicitly when legacy evidence is unacceptable:

```sh
python3 -I -B verify_review_intake.py --candidate ABS_CANDIDATE --selection ABS_SELECTION --intake ABS_INTAKE --require-bindings
```

Six-member v1 packets remain readable in the default mode, with
LEGACY_UNBOUND, EXACT_SELECTION_UNBOUND and HISTORICAL_POLICY_UNBOUND reported.
Their selection checks are semantic only. --require-bindings refuses them before
selection-control or candidate access. Unknown versions, partial v2 packets and
malformed bindings never fall back to v1. Packets are never rewritten/upgraded.
A coherent owner rewrite can impersonate legacy evidence; strict mode is required
to reject that downgrade. Bindings are unsigned consistency evidence, not source
authority, confidentiality, rights, authenticated human review or tamper-proof logs.

CONSISTENT exits1 and remains HOLD; STALE/DAMAGED exit2 and remain HOLD. Every
publication/export flag remains false. No repair, completion, copying or approval.
A packet check may read private packet metadata, selected control bytes and trusted
local policy source before candidate access; content_reads counts selected member
read attempts, not all filesystem reads. Snapshot checks assume stable owner storage.

Other entrypoints are source_export_gate.py,verify_source_export_receipt.py,
verify_batch_coverage.py and coverage_receipts.py. Use --help for required controls.
Explicit owner review assertions are not authenticated approval. The bundled
vendor/preupload_check.py is pinned by hash for optional text-screen seams; private
terms remain outside this package. The screen is incomplete and cannot clear
unknown confidentiality. Each batch is bounded; coverage checks never authorize
publication. Preserve partial outputs and known caller/process uncertainty;
never repair/adopt or automatically retry to obtain a clean status.
