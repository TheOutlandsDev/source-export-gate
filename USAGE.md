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

The builder writes CLAIM,proposal,review-draft,paired CHECKLIST and INTAKE-COMPLETE
metadata only. Six human review fields stay pending. Successful pending HOLD exits1;
input refusal/partial uncertainty exits2. Capture and reread counters are separate.

The verifier validates all six metadata members and hashes before candidate access,
then compares only the explicit current selection and selected bytes. CONSISTENT
exits1 and remains HOLD; STALE/DAMAGED exit2 and remain HOLD. It never repairs,
completes, copies or approves. Existing v0.9 packets lack persisted raw-selection
and historical-policy hashes: only semantic declarations/current bytes are checked.
Whitespace-equivalent selections may therefore be consistent.

Other entrypoints are source_export_gate.py,verify_source_export_receipt.py,
verify_batch_coverage.py and coverage_receipts.py. Use --help for required controls.
Explicit owner review assertions are not authenticated approval. The bundled
vendor/preupload_check.py is pinned by hash for optional text-screen seams; private
terms remain outside this package. The screen is incomplete and cannot clear
unknown confidentiality. Each batch is bounded; coverage checks never authorize
publication. Preserve partial outputs and known caller/process uncertainty;
never repair/adopt or automatically retry to obtain a clean status.
