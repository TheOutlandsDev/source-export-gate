"""Guarded unit regressions for unsigned, read-only declared batch coverage.

Only invented files and receipts are constructed. The metadata budget test uses
explicit mocked catalogs; real 129-file coverage is exercised separately.
"""

from contextlib import ExitStack, redirect_stdout
import copy
from io import StringIO
import json
import os
from pathlib import Path
import re
import unittest
from unittest.mock import patch

import verify_batch_coverage as coverage
from test_batch_coverage_cli import (FAMILIES, REPORT_FIELDS, batch_fixture, canonical,
    child_result, digest, invented_files, legacy_receipt, reseal, rewrite_result,
    snapshot, write_private, writer_args)


class BatchCoverageTests(unittest.TestCase):
    def setUp(self):
        self.guards = ExitStack()
        self.addCleanup(self.guards.close)
        self.denied = [self.guards.enter_context(patch(target, side_effect=AssertionError("external action forbidden")))
            for target in ("socket.socket", "socket.create_connection", "subprocess.Popen", "subprocess.run",
                           "os.execve", "os.system", "os.posix_spawn", "os.posix_spawnp", "os.fork")]

    def tearDown(self):
        for denied in self.denied:
            denied.assert_not_called()

    def writer(self, batch):
        with redirect_stdout(StringIO()):
            code = coverage.gate.main(writer_args(batch))
        self.assertIn(code, (0, 1))
        self.assertTrue((batch.fx.receipt / "COMPLETE.json").is_file())

    def validate(self, value):
        self.assertEqual(set(value), REPORT_FIELDS)
        self.assertEqual(value["format"], "outlands-batch-coverage-result-v1")
        self.assertIn(value["status"], {"MATCHED", "HOLD", "STALE", "UNVERIFIABLE", "REFUSED"})
        self.assertEqual(value["publication_status"], "HELD")
        for key in ("scanner_called", "publication_authorized", "export_performed", "destination_verified", "git_metadata_reviewed"):
            self.assertIs(value[key], False)
        for key in ("declared_files", "covered_files", "batch_count", "verified_batches", "content_reads"):
            self.assertIs(type(value[key]), int)
            self.assertGreaterEqual(value[key], 0)
        self.assertTrue(all(type(reason) is str and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", reason)
                            for reason in value["reason_codes"]))
        for row in value["batches"]:
            self.assertEqual(set(row), {"id", "status", "reason_codes", "eligibility", "text_review", "finding_count"})
        for finding in value["findings"]:
            self.assertEqual(set(finding), {"batch_id", "path", "check"})
            self.assertFalse(finding["path"].startswith("/"))
        if value["status"] != "MATCHED":
            self.assertIsNone(value["bindings"])
            self.assertNotEqual(value["text_review"], "PASS")

    def call(self, case, status, *, zero=False, permitted_changes=()):
        before = snapshot(case.root)
        with ExitStack() as stack:
            assessed = stack.enter_context(patch.object(coverage.gate, "assess", side_effect=AssertionError("must not reassess")))
            screened = stack.enter_context(patch.object(coverage.gate, "_screen_snapshot", side_effect=AssertionError("must not rescreen")))
            member = child = None
            if zero:
                member = stack.enter_context(patch.object(coverage.gate, "_read_member", side_effect=AssertionError("preflight read member")))
                child = stack.enter_context(patch.object(coverage.verifier, "verify", side_effect=AssertionError("preflight called verifier")))
            value = coverage.verify_coverage(case.manifest, case.plan)
        assessed.assert_not_called()
        screened.assert_not_called()
        if member is not None:
            member.assert_not_called()
            child.assert_not_called()
            self.assertEqual(value["content_reads"], 0)
        self.validate(value)
        self.assertEqual(value["status"], status)
        self.assertNotIn(str(case.root), json.dumps(value))
        after = snapshot(case.root)
        excluded = {str(path.relative_to(case.root)) for path in permitted_changes}
        self.assertEqual({key: row for key, row in before.items() if key not in excluded},
                         {key: row for key, row in after.items() if key not in excluded})
        return value

    def test_real_129_python_java_rows_128_plus_one_match_exact_raw_bindings(self):
        with batch_fixture() as case:
            case.make_receipts(self.writer)
            value = self.call(case, "MATCHED")
            self.assertEqual((value["declared_files"], value["covered_files"], value["content_reads"]), (129, 129, 129))
            self.assertEqual((value["verified_batches"], value["text_review"]), (2, "NOT_RUN"))
            binding = value["bindings"]
            self.assertEqual(set(binding), {"format", "manifest_sha256", "plan_sha256", "policy", "batches"})
            self.assertEqual(binding["format"], "outlands-batch-coverage-bindings-v1")
            self.assertEqual(binding["manifest_sha256"], digest(case.manifest.read_bytes()))
            self.assertEqual(binding["plan_sha256"], digest(case.plan.read_bytes()))
            self.assertEqual(binding["policy"], {"gate_sha256": digest(Path(coverage.gate.__file__).read_bytes()),
                "verifier_sha256": digest(Path(coverage.verifier.__file__).read_bytes()),
                "coverage_sha256": digest(Path(coverage.__file__).read_bytes())})
            for batch, row in zip(case.batches, binding["batches"]):
                self.assertEqual(set(row), {"id", "receipt_files", "proposal_sha256", "review_sha256", "screen"})
                self.assertEqual(row["receipt_files"], {path.name: digest(path.read_bytes()) for path in batch.fx.receipt.iterdir()})
                self.assertEqual(row["proposal_sha256"], digest(batch.fx.proposal.read_bytes()))
                self.assertEqual(row["review_sha256"], digest(batch.fx.review.read_bytes()))

    def test_real_129_screened_clean_and_recorded_findings_survive_readonly_verification(self):
        for finding in (False, True):
            with self.subTest(finding=finding), batch_fixture(screened=True, finding=finding) as case:
                case.make_receipts(self.writer)
                expected = [{"batch_id": batch.id, **item} for batch in case.batches
                            for item in child_result(batch)["findings"]]
                value = self.call(case, "MATCHED")
                self.assertEqual(value["findings"], expected)
                self.assertEqual(value["content_reads"], 129)
                self.assertEqual(value["text_review"], "REVIEW" if finding else "PASS")

    def test_all_families_and_exact_eight_disjoint_batches(self):
        for family in FAMILIES:
            with self.subTest(family=family), batch_fixture(counts=(1,) * 8, family=family) as case:
                case.make_receipts(self.writer)
                value = self.call(case, "MATCHED")
                self.assertEqual((value["batch_count"], value["verified_batches"], value["content_reads"]), (8, 8, 8))

    def test_missing_extra_hash_size_and_class_mismatches_stop_before_any_child_read(self):
        for change in ("missing", "extra", "hash", "bytes", "class", "synthetic"):
            with self.subTest(change=change), batch_fixture(counts=(1, 1)) as case:
                case.make_receipts(self.writer)
                rows = case.manifest_doc["files"]
                if change == "missing": rows.pop()
                elif change == "extra": rows.append(dict(rows[-1], path="z_extra.py"))
                elif change == "hash": rows[0]["sha256"] = "0" * 64
                elif change == "bytes": rows[0]["bytes"] += 1
                elif change == "class": rows[0]["artifact_kind"] = "documentation"
                else: rows[0]["synthetic_fixture"] = True
                case.save_manifest()
                self.call(case, "HOLD", zero=True)

    def test_duplicate_child_path_cannot_supply_missing_manifest_row(self):
        with batch_fixture(counts=(1, 1)) as case:
            case.make_receipts(self.writer)
            replacement = copy.deepcopy(child_result(case.batches[0])["bindings"]["files"])
            rewrite_result(case.batches[1], lambda value: value["bindings"].update(files=replacement))
            self.call(case, "HOLD", zero=True)

    def test_family_mode_policy_and_screen_bindings_mismatch_before_content(self):
        for change in ("family", "mode", "policy", "screen"):
            with self.subTest(change=change), batch_fixture(counts=(1, 1), screened=change == "screen") as case:
                case.make_receipts(self.writer)
                def mutate(value):
                    if change == "family": value["family"] = "code-atlas"
                    elif change == "policy": value["bindings"]["policy"]["engine_sha256"] = "0" * 64
                    elif change == "screen": value["bindings"]["screen"]["private_terms_sha256"] = "0" * 64
                if change == "mode":
                    case.manifest_doc["review_mode"] = "screened"
                    for batch, row in zip(case.batches, case.plan_doc["batches"]):
                        row.update(scanner=str(batch.fx.prepare_scanner()), private_terms=str(batch.fx.terms))
                    case.save_manifest()
                else: rewrite_result(case.batches[1], mutate)
                self.call(case, "HOLD", zero=True)

    def test_ineligible_lexical_paths_and_class_reject_even_without_receipts(self):
        for change in ("path", "class", "synthetic"):
            with self.subTest(change=change), batch_fixture(counts=(1, 1)) as case:
                row = case.manifest_doc["files"][0]
                if change == "path": row["path"] = "app.env"
                elif change == "class": row["artifact_kind"] = "runtime_record"
                else: row.update(artifact_kind="synthetic_example", synthetic_fixture=False)
                case.manifest_doc["files"].sort(key=lambda item: item["path"])
                case.save_manifest()
                with patch.object(coverage.verifier, "_receipt_snapshot", side_effect=AssertionError("ineligible read receipt")) as receipts:
                    self.call(case, "HOLD", zero=True)
                receipts.assert_not_called()

    def test_raw_manifest_hash_mismatch_is_a_hold_before_receipt_read(self):
        with batch_fixture(counts=(1, 1)) as case:
            write_private(case.manifest, case.manifest.read_bytes() + b" ", replace=True)
            self.call(case, "HOLD", zero=True)

    def test_malformed_manifest_json_types_duplicates_and_bounds_refuse(self):
        for change in ("duplicate-json", "nan", "bool-bytes", "unknown", "duplicate-row", "unsorted", "count", "total", "raw-limit"):
            with self.subTest(change=change), batch_fixture(counts=(1, 1)) as case:
                doc = case.manifest_doc
                if change == "duplicate-json": raw = b'{"format":"a","format":"b"}\n'
                elif change == "nan": raw = b'{"files":NaN}\n'
                elif change == "raw-limit": raw = b" " * 1048577
                else:
                    if change == "bool-bytes": doc["files"][0]["bytes"] = True
                    elif change == "unknown": doc["private_note"] = "INVENTED_DO_NOT_ECHO"
                    elif change == "duplicate-row": doc["files"].append(dict(doc["files"][-1]))
                    elif change == "unsorted": doc["files"].reverse()
                    elif change == "count":
                        doc["files"] = [dict(doc["files"][0], path="file%04d.py" % index) for index in range(1025)]
                    else:
                        doc["files"] = [dict(doc["files"][0], path="file%04d.py" % index, bytes=512000) for index in range(63)]
                    raw = canonical(doc)
                write_private(case.manifest, raw, replace=True)
                self.call(case, "REFUSED", zero=True)

    def test_plan_schema_ids_order_batch_limit_and_pairs_are_strict(self):
        for change in ("unknown", "duplicate", "unsorted", "nine", "id", "relative", "pair", "mode"):
            with self.subTest(change=change), batch_fixture(counts=(1, 1)) as case:
                rows = case.plan_doc["batches"]
                if change == "unknown": rows[0]["extra"] = "INVENTED_DO_NOT_ECHO"
                elif change == "duplicate": rows.append(dict(rows[-1]))
                elif change == "unsorted": rows.reverse()
                elif change == "nine": case.plan_doc["batches"] = [dict(rows[0], id="batch%02d" % index) for index in range(9)]
                elif change == "id": rows[0]["id"] = "../private"
                elif change == "relative": rows[0]["candidate"] = "relative-candidate"
                elif change == "pair": rows[0]["scanner"] = str(case.root / "invented.py")
                else: rows[0].update(scanner=str(case.root / "invented.py"), private_terms=str(case.root / "invented.json"))
                case.save_plan()
                self.call(case, "REFUSED", zero=True)

    def test_global_root_overlaps_and_nested_controls_refuse(self):
        for change in ("same-candidate", "same-receipt", "cross-root", "ancestor", "nested-control", "code-location"):
            with self.subTest(change=change), batch_fixture(counts=(1, 1)) as case:
                first, second = case.plan_doc["batches"]
                if change == "same-candidate": second["candidate"] = first["candidate"]
                elif change == "same-receipt": second["receipt"] = first["receipt"]
                elif change == "cross-root": second["candidate"] = first["receipt"]
                elif change == "ancestor": second["receipt"] = str(case.batches[0].fx.root)
                elif change == "nested-control": second["proposal"] = str(case.batches[0].fx.candidate / "control.json")
                else: second["proposal"] = coverage.gate.__file__
                case.save_plan()
                self.call(case, "REFUSED", zero=True)

    def test_control_hardlink_alias_is_rejected_before_child_contents(self):
        with batch_fixture(counts=(1, 1)) as case:
            first, second = case.batches
            second.fx.review.unlink()
            os.link(first.fx.proposal, second.fx.review)
            self.call(case, "REFUSED", zero=True)

    def test_partial_missing_and_legacy_receipts_remain_unverifiable(self):
        for change in ("complete", "result", "missing-root", "legacy"):
            with self.subTest(change=change), batch_fixture(counts=(1, 1)) as case:
                if change != "missing-root": case.make_receipts(self.writer)
                if change == "complete": (case.batches[0].fx.receipt / "COMPLETE.json").unlink()
                elif change == "result": (case.batches[0].fx.receipt / "result.json").unlink()
                elif change == "legacy": legacy_receipt(case.batches[0])
                self.call(case, "UNVERIFIABLE", zero=True)

    def test_completed_child_hold_is_preserved_not_promoted(self):
        with batch_fixture(counts=(1, 1)) as case:
            case.batches[0].fx.review_doc["files"][0]["confidentiality"] = "unknown"
            case.batches[0].fx.save_review()
            case.make_receipts(self.writer)
            old = child_result(case.batches[0])
            value = self.call(case, "HOLD", zero=True)
            self.assertEqual(value["batches"][0]["status"], old["eligibility"])
            self.assertEqual(value["batches"][0]["reason_codes"], old["reason_codes"])

    def test_child_null_bindings_are_incomplete_not_newly_assessed(self):
        with batch_fixture(counts=(1, 1)) as case:
            case.make_receipts(self.writer)
            rewrite_result(case.batches[0], lambda value: value.update(bindings=None))
            self.call(case, "UNVERIFIABLE", zero=True)

    def test_malformed_bound_mode_and_unsafe_receipt_refuse(self):
        for change in ("bound-mode", "member-mode", "root-mode", "symlink", "extra"):
            with self.subTest(change=change), batch_fixture(counts=(1, 1)) as case:
                case.make_receipts(self.writer)
                receipt = case.batches[0].fx.receipt
                if change == "bound-mode": rewrite_result(case.batches[0], lambda value: value["bindings"]["files"][0].update(mode="0644"))
                elif change == "member-mode": (receipt / "result.json").chmod(0o644)
                elif change == "root-mode": receipt.chmod(0o755)
                elif change == "extra": write_private(receipt / "extra.json", b"{}\n")
                else:
                    path = receipt / "result.json"
                    raw = path.read_bytes()
                    path.unlink()
                    outside = case.root / "invented-result.json"
                    write_private(outside, raw)
                    path.symlink_to(outside)
                self.call(case, "REFUSED", zero=True)

    def test_current_candidate_byte_mode_directory_and_membership_drift_stays_stale(self):
        for change in ("bytes", "mode", "directory-mode", "extra", "missing"):
            with self.subTest(change=change), batch_fixture(counts=(1, 1)) as case:
                case.make_receipts(self.writer)
                batch = case.batches[0]
                member = batch.fx.candidate / batch.fx.proposal_doc["files"][0]["path"]
                if change == "bytes": write_private(member, member.read_bytes().replace(b"Invented", b"Changed!"), replace=True)
                elif change == "mode": member.chmod(0o644)
                elif change == "directory-mode": member.parent.chmod(0o755)
                elif change == "missing": member.unlink()
                else: write_private(batch.fx.candidate / "extra.py", b"# invented extra\n")
                value = self.call(case, "STALE")
                self.assertEqual(value["verified_batches"], 0)
                self.assertEqual(value["batches"][1]["status"], "NOT_RUN")

    def test_preexisting_control_byte_and_screen_pin_drift_is_stale_without_member_reads(self):
        for change in ("proposal", "review", "terms", "scanner"):
            with self.subTest(change=change), batch_fixture(counts=(1, 1), screened=True) as case:
                case.make_receipts(self.writer)
                batch = case.batches[0]
                path = getattr(batch.fx, change) if change in {"proposal", "review"} else getattr(batch, change)
                write_private(path, path.read_bytes() + b" ", replace=True)
                self.call(case, "STALE", zero=True)

    def test_first_child_failure_stops_further_verification_and_retains_attempted_reads(self):
        with batch_fixture(counts=(1, 1)) as case:
            case.make_receipts(self.writer)
            original = coverage.verifier.verify
            calls = []
            def first_stale(*args, **kwargs):
                calls.append(args[0])
                response = original(*args, **kwargs)
                response.update(status="STALE", reason_codes=["CANDIDATE_CHANGED"])
                return response
            with patch.object(coverage.verifier, "verify", side_effect=first_stale):
                value = self.call(case, "STALE")
            self.assertEqual(len(calls), 1)
            self.assertEqual(value["content_reads"], 1)
            self.assertEqual(value["verified_batches"], 0)
            self.assertEqual(value["batches"][1]["status"], "NOT_RUN")

    def test_forged_child_authority_scanner_shape_or_read_count_never_promotes(self):
        changes = ({"publication_authorized": True}, {"scanner_called": True}, {"content_reads": True},
                   {"content_reads": 2}, {"extra": "INVENTED_DO_NOT_ECHO"})
        for change in changes:
            with self.subTest(change=change), batch_fixture(counts=(1, 1)) as case:
                case.make_receipts(self.writer)
                original = coverage.verifier.verify
                def forged(*args, **kwargs):
                    value = original(*args, **kwargs)
                    value.update(change)
                    return value
                with patch.object(coverage.verifier, "verify", side_effect=forged):
                    self.call(case, "REFUSED")

    def test_later_child_failure_retains_earlier_screen_findings(self):
        files = invented_files(2)
        first = sorted(files)[0]
        files[first] += b"// FICTIONAL_REVIEW_MARKER_47\n"
        with batch_fixture(files=files, counts=(1, 1), screened=True) as case:
            case.make_receipts(self.writer)
            batch = case.batches[1]
            member = batch.fx.candidate / batch.fx.proposal_doc["files"][0]["path"]
            write_private(member, member.read_bytes().replace(b"Invented", b"Changed!"), replace=True)
            value = self.call(case, "STALE")
            self.assertEqual(value["verified_batches"], 1)
            self.assertEqual(value["text_review"], "REVIEW")
            self.assertTrue(value["findings"])
            self.assertTrue(all(item["batch_id"] == case.batches[0].id for item in value["findings"]))

    def test_second_child_detects_late_mutation_of_earlier_proposal_review_or_terms(self):
        for target in ("proposal", "review", "terms"):
            with self.subTest(target=target), batch_fixture(counts=(1, 1), screened=True) as case:
                case.make_receipts(self.writer)
                first, second = case.batches
                path = first.terms if target == "terms" else getattr(first.fx, target)
                original, calls = coverage.verifier.verify, []
                def mutate_earlier(*args, **kwargs):
                    calls.append(args[0])
                    result = original(*args, **kwargs)
                    if args[0] == second.fx.candidate:
                        write_private(path, path.read_bytes() + b" ", replace=True)
                    return result
                with patch.object(coverage.verifier, "verify", side_effect=mutate_earlier):
                    value = self.call(case, "STALE", permitted_changes=(path,))
                self.assertEqual(len(calls), 2)
                self.assertEqual(value["content_reads"], 2)

    def test_late_manifest_and_plan_changes_are_stale(self):
        for target in ("manifest", "plan"):
            with self.subTest(target=target), batch_fixture(counts=(1, 1)) as case:
                case.make_receipts(self.writer)
                path = getattr(case, target)
                original = coverage.verifier.verify
                def mutate(*args, **kwargs):
                    value = original(*args, **kwargs)
                    if args[0] == case.batches[-1].fx.candidate:
                        write_private(path, path.read_bytes() + b" ", replace=True)
                    return value
                with patch.object(coverage.verifier, "verify", side_effect=mutate):
                    value = self.call(case, "STALE", permitted_changes=(path,))
                self.assertEqual(value["content_reads"], 2)

    def test_late_coherently_resealed_child_receipt_is_stale(self):
        with batch_fixture(counts=(1, 1)) as case:
            case.make_receipts(self.writer)
            first = case.batches[0].fx.receipt
            original = coverage.verifier.verify
            def mutate(*args, **kwargs):
                value = original(*args, **kwargs)
                if args[0] == case.batches[-1].fx.candidate:
                    for name in ("REVIEW.md", "REVIEW.txt"):
                        path = first / name
                        write_private(path, path.read_bytes() + b"\nInvented late note.\n", replace=True)
                    reseal(first)
                return value
            with patch.object(coverage.verifier, "verify", side_effect=mutate):
                value = self.call(case, "STALE", permitted_changes=tuple(first / name for name in ("REVIEW.md", "REVIEW.txt", "COMPLETE.json")))
            self.assertEqual(value["content_reads"], 2)

    def test_late_earlier_candidate_change_is_detected_after_last_child(self):
        with batch_fixture(counts=(1, 1)) as case:
            case.make_receipts(self.writer)
            first = case.batches[0]
            member = first.fx.candidate / first.fx.proposal_doc["files"][0]["path"]
            original = coverage.verifier.verify
            def mutate(*args, **kwargs):
                value = original(*args, **kwargs)
                if args[0] == case.batches[-1].fx.candidate:
                    write_private(member, member.read_bytes().replace(b"Invented", b"Changed!"), replace=True)
                return value
            with patch.object(coverage.verifier, "verify", side_effect=mutate):
                value = self.call(case, "STALE", permitted_changes=(member,))
            self.assertEqual(value["content_reads"], 2)

    def test_fixed_code_pin_changes_are_stale_without_editing_product(self):
        with batch_fixture(counts=(1, 1)) as case:
            case.make_receipts(self.writer)
            original, calls = coverage._code_snapshot, []
            def changed_code():
                value = original()
                calls.append(True)
                if len(calls) > 1:
                    pin, old_hash = value["coverage"]
                    value["coverage"] = (pin, "0" * 64 if old_hash != "0" * 64 else "1" * 64)
                return value
            with patch.object(coverage, "_code_snapshot", side_effect=changed_code):
                value = self.call(case, "STALE")
            self.assertEqual(value["content_reads"], 2)

    def test_shared_exact_screen_control_paths_are_allowed_but_different_terms_are_not(self):
        with batch_fixture(counts=(1, 1), screened=True) as case:
            case.make_receipts(self.writer)
            first = case.plan_doc["batches"][0]
            case.plan_doc["batches"][1].update(scanner=first["scanner"], private_terms=first["private_terms"])
            case.save_plan()
            self.call(case, "MATCHED")

    def test_full_manifest_metadata_above_eight_megabytes_does_not_use_arbitrary_chunk_budget(self):
        # Catalog-only boundary: valid 64+65 partitions each stay below 8MB,
        # while an arbitrary contiguous 128-row validation chunk exceeds 8MB.
        # Only the pure manifest validator is invoked, not content verification.
        rows = []
        for index in range(129):
            rows.append({"path": "file%04d.py" % index, "sha256": "0" * 64,
                         "bytes": 70000, "artifact_kind": "source", "synthetic_fixture": False})
        manifest = {"format": "outlands-batch-coverage-manifest-v1", "family": "agent-workbench",
                    "review_mode": "eligibility_only", "publication_authorized": False, "files": rows}
        self.assertGreater(sum(row["bytes"] for row in rows[:128]), 8000000)
        self.assertLessEqual(sum(row["bytes"] for row in rows[:64]), 8000000)
        self.assertLessEqual(sum(row["bytes"] for row in rows[64:]), 8000000)
        self.assertLess(sum(row["bytes"] for row in rows), 32000000)
        with patch.object(coverage.gate, "_read_member", side_effect=AssertionError("metadata validation read content")) as member:
            coverage._manifest(manifest)
        member.assert_not_called()

    def test_internal_exception_is_finite_and_never_echoes_private_error(self):
        with batch_fixture(counts=(1, 1)) as case:
            case.make_receipts(self.writer)
            with patch.object(coverage.verifier, "_receipt_snapshot", side_effect=RuntimeError("INVENTED_PRIVATE_ERROR /invented/private")):
                value = self.call(case, "REFUSED", zero=True)
            self.assertNotIn("INVENTED_PRIVATE_ERROR", json.dumps(value))
            self.assertEqual(value["reason_codes"], ["INTERNAL_REFUSAL"])


if __name__ == "__main__":
    unittest.main()
