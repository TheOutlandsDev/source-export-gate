# Source Export Gate

Local Python tools for preparing and checking explicitly selected source files.
Review declarations and matching hashes never grant publication approval.

- Assess declared source eligibility before a pinned offline text screen.
- Save and recheck private observations and batch coverage.
- Build metadata-only intake proposals with every review field pending.
- Verify pending intake integrity and selected-content freshness read-only.

Pending intake reviews remain HOLD, including when current hashes are consistent.
No source upload, Git action, provider request or automatic review approval occurs.
The tools target Linux with Python3.10+ and standard-library filesystem primitives.

See [usage](USAGE.md), [origins](ORIGINS.md), [license scope](LICENSE-STATUS.md)
and [third-party notices](THIRD-PARTY-NOTICES.md).

## Offline tests

Run from this package with a NEW output directory under an owner-private700 parent:

```sh
python3 -I -B run_tests.py --output /absolute/private/new-test-run
```

The runner expects246 methods/423 fixed CLI launches, six large-fixture proofs
and two pending-intake proofs. It creates private outputs outside the package;
never commit them. Test data are invented Python/Java/Unicode text, not executed
or compiled. Temporary case teardown remains; logs/results/proofs are retained.
The runner does not create OS namespaces itself; use an external namespace fence
when stronger process/network isolation is required. Tests record that distinction.
No automatic retries or adoption of old output directories.

## Limits

This is a bounded local review aid. Hashes and owner assertions are unsigned;
they do not prove authorship, confidentiality, redistribution rights, authenticated
human review, destination access, crash durability or atomic multiwriter behavior.
Sequential checks assume trusted stable owner storage. No whole-host/live/model
acceptance is implied.

## License

MIT; see [LICENSE](LICENSE) and [third-party notices](THIRD-PARTY-NOTICES.md).
This license covers the tool, not private candidate files or their publication.
