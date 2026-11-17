# v0.11 offline validation

Qualification recorded 2026-11-16 (America/New_York).

268 test methods in 13 suites and 425 fixed product CLI launches passed, with
zero failures, errors, skips, unexpected outcomes or denied external operations.
All source and private collector hashes were unchanged after execution.

The private collector supplied read-only relocated source, a fresh writable test
runtime, a cleared environment and separate network/process namespaces. It exited
0 and was reaped without cleanup. The public runner does not create namespaces
itself; namespace separation was supplied externally for this qualification.

## Evidence bindings

Fresh invented Python/Java/Unicode text covered v2 creation, exact persisted
selection and gate/builder policy hashes, strict verification and pending reviews.
Regressions covered selection reformatting, saved/current policy hash mismatches,
late policy drift, malformed/resealed/oversized binding data, numeric type changes,
member links, missing/extra files, unknown versions and late packet alteration.
Invalid bindings were checked before candidate root opens or content reads.
Strict legacy refusal also preceded selection-control reads.

Synthetic v1-shaped packets retained semantic-only checks and explicit
LEGACY_UNBOUND limits; no historical/private packet was opened or upgraded.
A controlled half-written evidence member remained UNVERIFIABLE without a
completion marker or retry. These are Python fault-injection tests, not native
crash, filesystem durability or hostile concurrent-owner qualification.

Six inherited large-fixture proofs used actual 129-file, 9,030,000-byte invented
text sets split into bounded batches. Two pending-intake proofs used three Unicode
files totaling 136 bytes and kept every review field pending; the existing source
gate returned HOLD/REVIEW_INCOMPLETE with zero selected-content reads.

## Launch history and limits

The first qualification launch was blocked by the command sandbox during bwrap
network setup, before the test runner started. Its failure was retained privately.
The owner explicitly approved one fresh isolated qualification outside that command
sandbox; bwrap isolation remained in place and that run passed. No automatic retry
or old interruption-worker/history rerun occurred.

No real project/user data, actual Java compilation, live provider, model inference,
independent-author audit or GitHub CI is claimed. Private logs, receipts, terms and
fixture outputs are excluded from the repository. Hashes are unsigned consistency
evidence under trusted stable owner storage, not authenticated review, ownership,
rights, confidentiality or release permission. No test releases any held input.
