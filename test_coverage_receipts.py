"""Saved coverage integrity, freshness and retained controlled-write failures.

Only newly invented trees are used. Fault injection is synchronous through the
writer seam; it does not prove native crash recovery or filesystem durability.
"""

from contextlib import ExitStack, redirect_stdout
import errno
from io import StringIO
import json
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import patch

import coverage_receipts as receipts
from test_coverage_receipts_cli import (PACKET_FILES, SAVE_FIELDS, VERIFY_FIELDS,
    actual_bytes, canonical, child_result, coverage_fixture, digest, packet_record,
    reseal_packet, rewrite_record, snapshot, write_private, writer_args)


WRITE_ORDER = ("CLAIM.json", "record.json", "REVIEW.md", "REVIEW.txt", "COMPLETE.json")


class CoverageReceiptsTests(unittest.TestCase):
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
            code = receipts.gate.main(writer_args(batch))
        self.assertIn(code, (0, 1))
        self.assertIsNotNone(child_result(batch)["bindings"])

    def validate(self, value, save=False):
        self.assertEqual(set(value), SAVE_FIELDS if save else VERIFY_FIELDS)
        self.assertEqual(value["format"], "outlands-private-coverage-save-v1" if save
                         else "outlands-private-coverage-verification-v1")
        self.assertEqual(value["publication_status"], "HELD")
        for key in ("scanner_called", "publication_authorized", "export_performed", "destination_verified", "git_metadata_reviewed"):
            self.assertIs(value[key], False)
        for key in ("finding_count", "content_reads"):
            self.assertIs(type(value[key]), int)
            self.assertGreaterEqual(value[key], 0)
        self.assertIn(value["text_review"], {"NOT_RUN", "PASS", "REVIEW"})
        self.assertIs(type(value["reason_codes"]), list)
        for reason in value["reason_codes"]:
            self.assertIs(type(reason), str)
            self.assertRegex(reason, r"^[A-Z][A-Z0-9_]{0,63}$")
        self.assertNotIn("INVENTED_DO_NOT_ECHO", json.dumps(value))

    def _guards(self, stack, *, zero=False):
        assessed = stack.enter_context(patch.object(receipts.gate, "assess", side_effect=AssertionError("receipt reassessed")))
        screened = stack.enter_context(patch.object(receipts.gate, "_screen_snapshot", side_effect=AssertionError("receipt rescreened")))
        original_member = receipts.gate._read_member
        returned = []
        def observe(*args, **kwargs):
            raw = original_member(*args, **kwargs)
            self.assertIs(type(raw), bytes)
            returned.append(len(raw))
            return raw
        member = stack.enter_context(patch.object(receipts.gate, "_read_member",
            side_effect=AssertionError("invalid packet read a member") if zero else observe))
        original_checker = receipts.coverage.verify_coverage
        checker = stack.enter_context(patch.object(receipts.coverage, "verify_coverage",
            side_effect=AssertionError("invalid packet rechecked coverage") if zero else original_checker))
        return assessed, screened, member, checker, returned

    def _assert_guards(self, guards, *, zero=False):
        assessed, screened, member, checker, returned = guards
        assessed.assert_not_called()
        screened.assert_not_called()
        if zero:
            member.assert_not_called()
            checker.assert_not_called()
        return member, checker, returned

    def save(self, case, status="SAVED", *, zero=False, receipt=None):
        before = snapshot(case.root)
        with ExitStack() as stack:
            guards = self._guards(stack, zero=zero)
            value = receipts.save_coverage(case.manifest, case.plan, case.packet if receipt is None else receipt)
        member, checker, returned = self._assert_guards(guards, zero=zero)
        self.validate(value, save=True)
        self.assertEqual(value["status"], status)
        self.assertEqual(value["content_reads"], member.call_count)
        self.assertNotIn(str(case.root), json.dumps(value))
        after = snapshot(case.root)
        for name, row in before.items():
            self.assertEqual(after[name][:4] if name == "." else after[name], row[:4] if name == "." else row)
        new = set(after) - set(before)
        self.assertTrue(all(name == "coverage-packet" or name.startswith("coverage-packet/") for name in new))
        if status == "SAVED":
            self.assertEqual(new, {"coverage-packet", *("coverage-packet/" + name for name in PACKET_FILES)})
        return value, returned, checker.call_count

    def verify(self, case, status="MATCHED", *, zero=False, permitted_changes=()):
        before = snapshot(case.root)
        with ExitStack() as stack:
            guards = self._guards(stack, zero=zero)
            value = receipts.verify_receipt(case.manifest, case.plan, case.packet)
        member, checker, returned = self._assert_guards(guards, zero=zero)
        self.validate(value)
        self.assertEqual(value["status"], status)
        self.assertEqual(value["content_reads"], member.call_count)
        self.assertNotIn(str(case.root), json.dumps(value))
        excluded = {str(path.relative_to(case.root)) for path in permitted_changes}
        after = snapshot(case.root)
        self.assertEqual({name: row for name, row in before.items() if name not in excluded},
                         {name: row for name, row in after.items() if name not in excluded})
        return value, returned, checker.call_count

    def test_actual_large_clean_and_findings_save_verify_exact_buffers_and_packet_hashes(self):
        for finding in (False, True):
            with self.subTest(finding=finding), coverage_fixture(self.writer, large=True, screened=True, finding=finding) as case:
                observed, totals = actual_bytes(case)
                self.assertEqual((len(observed), set(observed.values()), totals), (129, {70000}, [4480000, 4550000]))
                saved, returned, calls = self.save(case)
                self.assertEqual((saved["coverage_status"], saved["content_reads"], calls, sum(returned)), ("MATCHED", 129, 1, 9030000))
                self.assertEqual(saved["text_review"], "REVIEW" if finding else "PASS")
                record = packet_record(case)
                self.assertEqual(set(record), {"format", "inputs", "policy", "report"})
                self.assertEqual(record["format"], "outlands-private-coverage-record-v1")
                self.assertEqual(record["inputs"], {"manifest_sha256": digest(case.manifest.read_bytes()), "plan_sha256": digest(case.plan.read_bytes())})
                self.assertEqual(record["policy"], {"receipts_sha256": digest(Path(receipts.__file__).read_bytes())})
                self.assertEqual(record["report"]["findings"], [{"batch_id": batch.id, **row}
                    for batch in case.batches for row in child_result(batch)["findings"]])
                self.assertEqual(json.loads((case.packet / "COMPLETE.json").read_bytes()), {
                    "format": "outlands-private-coverage-complete-v1", "files": {
                        name: digest((case.packet / name).read_bytes()) for name in PACKET_FILES - {"COMPLETE.json"}}})
                self.assertEqual((case.packet / "REVIEW.md").read_bytes(), (case.packet / "REVIEW.txt").read_bytes())
                for path in case.packet.iterdir():
                    info = path.lstat()
                    self.assertEqual((stat.S_IMODE(info.st_mode), info.st_uid, info.st_nlink), (0o600, os.getuid(), 1))
                verified, read_back, calls = self.verify(case)
                self.assertEqual((verified["integrity"], verified["freshness"], verified["saved_status"], calls), ("MATCHED", "MATCHED", "MATCHED", 1))
                self.assertEqual((verified["content_reads"], sum(read_back), verified["finding_count"]), (129, 9030000, saved["finding_count"]))

    def test_small_eligibility_packet_preserves_unscreened_status(self):
        with coverage_fixture(self.writer) as case:
            saved, _, calls = self.save(case)
            verified, _, checked = self.verify(case)
            self.assertEqual((saved["text_review"], verified["text_review"], calls, checked), ("NOT_RUN", "NOT_RUN", 1, 1))

    def test_saved_hold_findings_stay_unverifiable_without_any_recheck(self):
        with coverage_fixture(self.writer, screened=True, finding=True, held=True) as case:
            saved, _, _ = self.save(case)
            self.assertEqual(saved["coverage_status"], "HOLD")
            self.assertGreater(saved["finding_count"], 0)
            value, returned, calls = self.verify(case, "UNVERIFIABLE", zero=True)
            self.assertEqual((value["saved_status"], value["text_review"], value["finding_count"], calls, returned),
                             ("HOLD", "REVIEW", saved["finding_count"], 0, []))

    def test_save_existing_unsafe_and_overlapping_destinations_before_checker(self):
        for change in ("existing", "candidate", "child-receipt", "control", "ancestor", "nonprivate-parent", "symlink"):
            with self.subTest(change=change), coverage_fixture(self.writer) as case:
                target = case.packet
                if change == "existing": target.mkdir(mode=0o700)
                elif change == "candidate": target = case.batches[0].fx.candidate / "packet"
                elif change == "child-receipt": target = case.batches[0].fx.receipt / "packet"
                elif change == "control": target = case.manifest
                elif change == "ancestor": target = case.root
                elif change == "nonprivate-parent":
                    parent = case.root / "public-parent"
                    parent.mkdir(mode=0o700)
                    parent.chmod(0o755)
                    target = parent / "packet"
                else: target.symlink_to(case.batches[0].fx.receipt, target_is_directory=True)
                self.save(case, "REFUSED", zero=True, receipt=target)

    def test_schema_and_control_location_fail_before_destination_mutation(self):
        for change in ("manifest", "plan", "alias", "code"):
            with self.subTest(change=change), coverage_fixture(self.writer) as case:
                if change == "manifest": write_private(case.manifest, b'{"INVENTED_DO_NOT_ECHO":true}\n', replace=True)
                elif change == "plan": write_private(case.plan, b'{"format":"x","format":"y"}\n', replace=True)
                elif change == "alias":
                    case.plan.unlink()
                    os.link(case.manifest, case.plan)
                else:
                    with patch.object(receipts, "__file__", str(case.batches[0].fx.candidate / "invented.py")):
                        self.save(case, "REFUSED", zero=True)
                    continue
                self.save(case, "REFUSED", zero=True)
                self.assertFalse(case.packet.exists())

    def test_oserror_before_each_write_retains_partial_and_known_observation(self):
        for stop_name in WRITE_ORDER:
            with self.subTest(stop_name=stop_name), coverage_fixture(self.writer) as case:
                original, attempted = receipts._write_new, []
                def fail(fd, name, raw):
                    attempted.append(name)
                    if name == stop_name:
                        raise OSError("INVENTED_DO_NOT_ECHO")
                    return original(fd, name, raw)
                with patch.object(receipts, "_write_new", side_effect=fail):
                    value, returned, calls = self.save(case, "REFUSED")
                index = WRITE_ORDER.index(stop_name)
                self.assertEqual(attempted, list(WRITE_ORDER[:index + 1]))
                self.assertEqual({path.name for path in case.packet.iterdir()}, set(WRITE_ORDER[:index]))
                self.assertEqual((value["coverage_status"], value["content_reads"], sum(returned), calls), ("MATCHED", 2, 512, 1))
                self.verify(case, "UNVERIFIABLE", zero=True)

    def test_half_written_file_is_retained_and_not_repaired(self):
        with coverage_fixture(self.writer) as case:
            original = receipts._write_new
            def half(fd, name, raw):
                if name == "record.json":
                    original(fd, name, raw[:len(raw) // 2])
                    raise OSError("injected half-file write")
                return original(fd, name, raw)
            with patch.object(receipts, "_write_new", side_effect=half):
                value, _, _ = self.save(case, "REFUSED")
            self.assertEqual(value["content_reads"], 2)
            self.assertEqual({path.name for path in case.packet.iterdir()}, {"CLAIM.json", "record.json"})
            self.assertGreater((case.packet / "record.json").stat().st_size, 0)
            self.verify(case, "UNVERIFIABLE", zero=True)

    def test_actual_large_interrupted_completion_keeps_129_read_evidence_unqualified(self):
        with coverage_fixture(self.writer, large=True) as case:
            before = snapshot(case.root)
            original, attempted, directory_fds = receipts._write_new, [], []
            def interrupt(fd, name, raw):
                attempted.append(name)
                directory_fds.append(fd)
                if name == "COMPLETE.json":
                    raise KeyboardInterrupt("controlled fixture interruption")
                return original(fd, name, raw)
            with ExitStack() as stack:
                guards = self._guards(stack)
                stack.enter_context(patch.object(receipts, "_write_new", side_effect=interrupt))
                with self.assertRaises(KeyboardInterrupt):
                    receipts.save_coverage(case.manifest, case.plan, case.packet)
            member, checker, returned = self._assert_guards(guards)
            for fd in set(directory_fds):
                with self.assertRaises(OSError) as failure:
                    os.fstat(fd)
                self.assertEqual(failure.exception.errno, errno.EBADF)
            self.assertEqual((member.call_count, checker.call_count, sum(returned)), (129, 1, 9030000))
            self.assertEqual(attempted, list(WRITE_ORDER))
            self.assertEqual({path.name for path in case.packet.iterdir()}, PACKET_FILES - {"COMPLETE.json"})
            self.assertEqual(packet_record(case)["report"]["content_reads"], 129)
            after = snapshot(case.root)
            for name, row in before.items():
                self.assertEqual(after[name][:4] if name == "." else after[name], row[:4] if name == "." else row)
            self.verify(case, "UNVERIFIABLE", zero=True)

    def test_actual_large_input_drift_is_stale_without_members(self):
        with coverage_fixture(self.writer, large=True) as case:
            self.save(case)
            write_private(case.plan, case.plan.read_bytes() + b" ", replace=True)
            value, returned, calls = self.verify(case, "STALE", zero=True)
            self.assertEqual((value["saved_status"], returned, calls), ("MATCHED", [], 0))

    def test_missing_partial_and_foreign_packets_do_not_read_candidates(self):
        for change in ("missing", "complete", "record", "note", "foreign"):
            with self.subTest(change=change), coverage_fixture(self.writer) as case:
                if change != "missing": self.save(case)
                if change in {"complete", "record", "note"}:
                    (case.packet / {"complete": "COMPLETE.json", "record": "record.json", "note": "REVIEW.txt"}[change]).unlink()
                elif change == "foreign":
                    write_private(case.packet / "CLAIM.json", canonical({"format": "outlands-source-export-claim-v2",
                        "publication_authorized": False, "export_performed": False}), replace=True)
                    reseal_packet(case.packet)
                self.verify(case, "REFUSED" if change == "foreign" else "UNVERIFIABLE", zero=True)

    def test_unsafe_packet_links_modes_extra_and_special_files_refuse(self):
        for change in ("file-mode", "directory-mode", "extra", "symlink", "hardlink", "fifo"):
            with self.subTest(change=change), coverage_fixture(self.writer) as case:
                self.save(case)
                path = case.packet / "record.json"
                if change == "file-mode": path.chmod(0o644)
                elif change == "directory-mode": case.packet.chmod(0o755)
                elif change == "extra": write_private(case.packet / "extra.json", b"{}\n")
                else:
                    outside = case.root / "invented-record.json"
                    write_private(outside, path.read_bytes())
                    path.unlink()
                    if change == "symlink": path.symlink_to(outside)
                    elif change == "hardlink": os.link(outside, path)
                    else: os.mkfifo(path, mode=0o600)
                self.verify(case, "REFUSED", zero=True)

    def test_raw_packet_tamper_duplicate_json_nonfinite_and_utf8_refuse(self):
        for change in ("checksum", "duplicate", "nonfinite", "claim-zero", "utf8", "nul", "notes-differ"):
            with self.subTest(change=change), coverage_fixture(self.writer) as case:
                self.save(case)
                if change == "checksum": write_private(case.packet / "record.json", (case.packet / "record.json").read_bytes() + b" ", replace=True)
                elif change == "duplicate":
                    write_private(case.packet / "record.json", b'{"format":"a","format":"b"}\n', replace=True)
                    reseal_packet(case.packet)
                elif change == "nonfinite":
                    write_private(case.packet / "record.json", b'{"report":NaN}\n', replace=True)
                    reseal_packet(case.packet)
                elif change == "claim-zero":
                    write_private(case.packet / "CLAIM.json", canonical({
                        "format": "outlands-private-coverage-claim-v1",
                        "publication_authorized": 0, "export_performed": 0}), replace=True)
                    reseal_packet(case.packet)
                else:
                    for name in ("REVIEW.md", "REVIEW.txt"):
                        write_private(case.packet / name, b"\xff" if change == "utf8" else b"invented\x00note" if change == "nul" else name.encode(), replace=True)
                    reseal_packet(case.packet)
                self.verify(case, "REFUSED", zero=True)

    def test_resealed_report_schema_counter_authority_and_finding_contradictions_refuse(self):
        changes = ("extra", "bool", "negative", "limit", "authority", "status", "reason", "covered", "reads",
                   "verified", "ids", "finding-count", "binding-input", "screen-mode", "policy", "binding-extra")
        for change in changes:
            with self.subTest(change=change), coverage_fixture(self.writer) as case:
                self.save(case)
                def mutate(record):
                    report = record["report"]
                    if change == "extra": report["extra"] = "INVENTED_DO_NOT_ECHO"
                    elif change == "bool": report["declared_files"] = True
                    elif change == "negative": report["covered_files"] = -1
                    elif change == "limit": report["declared_files"] = 1025
                    elif change == "authority": report["export_performed"] = True
                    elif change == "status": report["status"] = "SUCCESS"
                    elif change == "reason": report["reason_codes"] = ["UNEXPECTED_ON_MATCHED"]
                    elif change == "covered": report["covered_files"] = 1
                    elif change == "reads": report["content_reads"] = 1
                    elif change == "verified": report["verified_batches"] = 1
                    elif change == "ids": report["batches"][1]["id"] = report["batches"][0]["id"]
                    elif change == "finding-count": report["batches"][0]["finding_count"] = 1
                    elif change == "binding-input": record["inputs"]["manifest_sha256"] = "0" * 64
                    elif change == "screen-mode": report["text_review"] = "PASS"
                    elif change == "policy": report["bindings"]["policy"]["gate_sha256"] = "invalid"
                    else: report["bindings"]["extra"] = False
                rewrite_record(case, mutate)
                self.verify(case, "REFUSED", zero=True)

    def test_resealed_screen_and_grouped_finding_inconsistencies_refuse(self):
        for change in ("different-screen", "unknown-batch", "unknown-count", "review-without-findings"):
            with self.subTest(change=change), coverage_fixture(self.writer, screened=True, finding=True) as case:
                self.save(case)
                def mutate(record):
                    report = record["report"]
                    if change == "different-screen": report["bindings"]["batches"][1]["screen"]["private_terms_sha256"] = "0" * 64
                    elif change == "unknown-batch": report["findings"][0]["batch_id"] = "unlisted"
                    elif change == "unknown-count": report["batches"][1]["finding_count"] += 1
                    else:
                        report["findings"] = []
                        for row in report["batches"]: row["finding_count"] = 0
                rewrite_record(case, mutate)
                self.verify(case, "REFUSED", zero=True)

    def test_saved_code_and_input_pins_stale_before_checker_without_product_edits(self):
        for change in ("policy", "manifest", "plan", "old-policy"):
            with self.subTest(change=change), coverage_fixture(self.writer) as case:
                self.save(case)
                if change == "policy": rewrite_record(case, lambda value: value["policy"].update(receipts_sha256="0" * 64))
                elif change == "old-policy": rewrite_record(case, lambda value: value["report"]["bindings"]["policy"].update(gate_sha256="0" * 64))
                else:
                    path = getattr(case, change)
                    write_private(path, path.read_bytes() + b" ", replace=True)
                self.verify(case, "STALE", zero=True)

    def test_current_child_control_receipt_and_candidate_changes_are_stale(self):
        for change in ("proposal", "review", "child-note", "child-complete", "candidate", "candidate-mode"):
            with self.subTest(change=change), coverage_fixture(self.writer) as case:
                self.save(case)
                batch = case.batches[0]
                if change in {"proposal", "review"}:
                    path = getattr(batch.fx, change)
                    write_private(path, path.read_bytes() + b" ", replace=True)
                elif change == "child-note":
                    from test_batch_coverage_cli import reseal
                    for name in ("REVIEW.md", "REVIEW.txt"):
                        path = batch.fx.receipt / name
                        write_private(path, path.read_bytes() + b"\nInvented child note.\n", replace=True)
                    reseal(batch.fx.receipt)
                elif change == "child-complete":
                    (batch.fx.receipt / "COMPLETE.json").unlink()
                else:
                    path = batch.fx.candidate / batch.fx.proposal_doc["files"][0]["path"]
                    if change == "candidate-mode": path.chmod(0o644)
                    else: write_private(path, path.read_bytes().replace(b"Invented", b"Modified", 1), replace=True)
                value, _, _ = self.verify(case, "UNVERIFIABLE" if change == "child-complete" else "STALE",
                                          zero=change == "child-complete")
                self.assertEqual(value["saved_status"], "MATCHED")

    def test_late_manifest_plan_and_earlier_controls_are_stale_retaining_reads(self):
        for target in ("manifest", "plan", "proposal", "review", "terms"):
            with self.subTest(target=target), coverage_fixture(self.writer, screened=True) as case:
                self.save(case)
                path = getattr(case, target) if target in {"manifest", "plan"} else case.batches[0].terms if target == "terms" else getattr(case.batches[0].fx, target)
                original = receipts.coverage.verify_coverage
                def late(*args, **kwargs):
                    value = original(*args, **kwargs)
                    write_private(path, path.read_bytes() + b" ", replace=True)
                    return value
                with patch.object(receipts.coverage, "verify_coverage", side_effect=late):
                    value, returned, calls = self.verify(case, "STALE", permitted_changes=(path,))
                self.assertEqual((value["content_reads"], sum(returned), calls), (2, 512, 1))

    def test_late_earlier_candidate_and_packet_reseal_are_stale(self):
        for change in ("candidate", "packet"):
            with self.subTest(change=change), coverage_fixture(self.writer) as case:
                self.save(case)
                original = receipts.coverage.verify_coverage
                batch = case.batches[0]
                member = batch.fx.candidate / batch.fx.proposal_doc["files"][0]["path"]
                paths = (member,) if change == "candidate" else tuple(case.packet / name for name in ("REVIEW.md", "REVIEW.txt", "COMPLETE.json"))
                def late(*args, **kwargs):
                    value = original(*args, **kwargs)
                    if change == "candidate": write_private(member, member.read_bytes().replace(b"Invented", b"Modified", 1), replace=True)
                    else:
                        for name in ("REVIEW.md", "REVIEW.txt"):
                            path = case.packet / name
                            write_private(path, path.read_bytes() + b"\nInvented late note.\n", replace=True)
                        reseal_packet(case.packet)
                    return value
                with patch.object(receipts.coverage, "verify_coverage", side_effect=late):
                    value, returned, calls = self.verify(case, "STALE", permitted_changes=paths)
                self.assertEqual((value["content_reads"], sum(returned), calls), (2, 512, 1))

    def test_save_rejects_late_input_drift_before_completion_without_losing_observation(self):
        with coverage_fixture(self.writer) as case:
            before = snapshot(case.root)
            original = receipts.coverage.verify_coverage
            def drift(*args, **kwargs):
                value = original(*args, **kwargs)
                write_private(case.plan, case.plan.read_bytes() + b" ", replace=True)
                return value
            with patch.object(receipts.coverage, "verify_coverage", side_effect=drift):
                with ExitStack() as stack:
                    guards = self._guards(stack)
                    value = receipts.save_coverage(case.manifest, case.plan, case.packet)
            member, checker, returned = self._assert_guards(guards)
            self.validate(value, save=True)
            self.assertEqual((value["status"], value["content_reads"], sum(returned), checker.call_count), ("REFUSED", 2, 512, 1))
            self.assertFalse((case.packet / "COMPLETE.json").exists())
            after = snapshot(case.root)
            for name, row in before.items():
                if name == str(case.plan.relative_to(case.root)):
                    continue
                self.assertEqual(after[name][:4] if name == "." else after[name], row[:4] if name == "." else row)
            self.assertTrue(all(name == "coverage-packet" or name.startswith("coverage-packet/")
                                for name in set(after) - set(before)))


if __name__ == "__main__":
    unittest.main()
