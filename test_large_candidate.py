"""Actual large invented text through the unchanged, read-only library checker.

Qualification requires the reviewed offline runner. These fixtures are never
executed or compiled, and no live source, provider or held task is inspected.
"""

from contextlib import ExitStack, redirect_stdout
from io import StringIO
import json
import os
import unittest
from unittest.mock import patch

import verify_batch_coverage as coverage
from test_batch_coverage_cli import REPORT_FIELDS
from test_large_candidate_cli import (canonical, child_result, digest, large_fixture,
    measure_and_record, snapshot, write_private, writer_args)


MEASUREMENT_FIELDS = {"format", "label", "file_count", "actual_total_bytes", "files_per_batch",
                      "bytes_per_batch", "min_file_bytes", "max_file_bytes", "all_files_utf8",
                      "source_map_sha256", "result_status", "text_review", "content_reads",
                      "scanner_called", "member_bytes_observed", "publication_authorized"}


class LargeCandidateTests(unittest.TestCase):
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
        # Receipt preparation is separate from the guarded read-only check.
        previous_umask = os.umask(0o077)
        output = StringIO()
        try:
            with redirect_stdout(output):
                code = coverage.gate.main(writer_args(batch))
        finally:
            os.umask(previous_umask)
        self.assertIn(code, (0, 1))
        self.assertTrue((batch.fx.receipt / "COMPLETE.json").is_file())
        summary = json.loads(output.getvalue())
        self.assertEqual(summary["eligibility"], "ELIGIBLE_FOR_TEXT_REVIEW")
        self.assertIs(summary["publication_authorized"], False)
        self.assertIsNotNone(child_result(batch)["bindings"])

    def _checked(self, case, expected_status, *, after_child=None, permitted_changes=()):
        before = snapshot(case.root)
        measured = {"bytes": 0, "lengths": [], "paths": []}
        original_member = coverage.gate._read_member
        original_verify = coverage.verifier.verify
        completed_children = []

        def actual_member(*args, **kwargs):
            raw = original_member(*args, **kwargs)
            self.assertIs(type(raw), bytes)
            measured["bytes"] += len(raw)
            measured["lengths"].append(len(raw))
            measured["paths"].append(args[1])
            return raw

        def actual_child(*args, **kwargs):
            result = original_verify(*args, **kwargs)
            completed_children.append(result)
            if after_child is not None:
                after_child(len(completed_children), result)
            return result

        with ExitStack() as stack:
            assessed = stack.enter_context(patch.object(coverage.gate, "assess", side_effect=AssertionError("must not reassess")))
            screened = stack.enter_context(patch.object(coverage.gate, "_screen_snapshot", side_effect=AssertionError("must not rescreen")))
            members = stack.enter_context(patch.object(coverage.gate, "_read_member", side_effect=actual_member))
            children = stack.enter_context(patch.object(coverage.verifier, "verify", side_effect=actual_child))
            report = coverage.verify_coverage(case.manifest, case.plan)
        assessed.assert_not_called()
        screened.assert_not_called()
        self.assertEqual(set(report), REPORT_FIELDS)
        self.assertEqual(report["status"], expected_status)
        self.assertEqual(report["content_reads"], members.call_count)
        self.assertEqual(children.call_count, len(completed_children))
        self.assertEqual(report["publication_status"], "HELD")
        for name in ("publication_authorized", "export_performed", "destination_verified",
                     "git_metadata_reviewed", "scanner_called"):
            self.assertIs(report[name], False)
        self.assertNotIn(str(case.root), json.dumps(report))
        if expected_status != "MATCHED":
            self.assertIsNone(report["bindings"])
            self.assertNotEqual(report["text_review"], "PASS")
        after = snapshot(case.root)
        excluded = {str(path.relative_to(case.root)) for path in permitted_changes}
        self.assertEqual({name: row for name, row in before.items() if name not in excluded},
                         {name: row for name, row in after.items() if name not in excluded})
        for name in excluded:
            # The test's deliberate write must not replace the inode or alter mode/links.
            self.assertEqual(before[name][:5], after[name][:5])
        return report, measured, completed_children

    def _profile(self, label, *, screened=False, finding=False):
        with large_fixture(screened=screened, finding=finding) as case:
            self.assertEqual(len(case.files), 129)
            self.assertEqual({name.rsplit(".", 1)[-1] for name in case.files}, {"py", "java"})
            self.assertTrue(all(len(raw) == 70000 and any(byte >= 128 for byte in raw)
                                for raw in case.files.values()))
            case.make_receipts(self.writer)
            findings = [{"batch_id": batch.id, **finding_row} for batch in case.batches
                        for finding_row in child_result(batch)["findings"]]
            before = snapshot(case.root)
            report, measured, children = self._checked(case, "MATCHED")
            expected_text = "REVIEW" if finding else "PASS" if screened else "NOT_RUN"
            self.assertEqual((report["declared_files"], report["covered_files"], report["content_reads"]), (129, 129, 129))
            self.assertEqual((report["batch_count"], report["verified_batches"]), (2, 2))
            self.assertEqual(report["text_review"], expected_text)
            self.assertEqual(report["findings"], findings)
            self.assertEqual(bool(findings), finding)
            self.assertEqual([child["content_reads"] for child in children], [64, 65])
            self.assertEqual(measured["lengths"], [70000] * 129)
            self.assertEqual(measured["bytes"], 9030000)
            self.assertEqual(measured["paths"], sorted(case.files))
            measurement = measure_and_record(case, label, report, member_bytes=measured["bytes"])
            self.assertEqual(set(measurement), MEASUREMENT_FIELDS)
            self.assertEqual(measurement["format"], "outlands-large-candidate-measurement-v1")
            self.assertEqual(measurement["label"], label)
            self.assertEqual((measurement["file_count"], measurement["actual_total_bytes"]), (129, 9030000))
            self.assertEqual(measurement["files_per_batch"], [64, 65])
            self.assertEqual(measurement["bytes_per_batch"], [4480000, 4550000])
            self.assertEqual((measurement["min_file_bytes"], measurement["max_file_bytes"]), (70000, 70000))
            self.assertIs(measurement["all_files_utf8"], True)
            self.assertEqual((measurement["result_status"], measurement["text_review"], measurement["content_reads"]),
                             ("MATCHED", expected_text, 129))
            self.assertEqual(measurement["member_bytes_observed"], 9030000)
            self.assertIs(measurement["publication_authorized"], False)
            self.assertIs(measurement["scanner_called"], False)
            measured_rows = []
            for batch in case.batches:
                for row in batch.fx.proposal_doc["files"]:
                    raw = (batch.fx.candidate / row["path"]).read_bytes()
                    raw.decode("utf-8")
                    measured_rows.append({"path": row["path"], "sha256": digest(raw), "bytes": len(raw)})
            self.assertEqual(measurement["source_map_sha256"],
                             digest(canonical(sorted(measured_rows, key=lambda row: row["path"]))))
            self.assertEqual(snapshot(case.root), before)

    @staticmethod
    def _change_one_ascii_byte(raw):
        offset = next(index for index, byte in enumerate(raw) if 65 <= byte <= 90)
        replacement = b"Y" if raw[offset:offset + 1] == b"Z" else b"Z"
        return raw[:offset] + replacement + raw[offset + 1:]

    def test_actual_9030000_bytes_eligibility_profile(self):
        self._profile("unit-eligibility")

    def test_actual_9030000_bytes_screened_clean_profile(self):
        self._profile("unit-screen-clean", screened=True)

    def test_actual_9030000_bytes_screened_finding_profile(self):
        self._profile("unit-screen-finding", screened=True, finding=True)

    def test_second_batch_same_size_mutation_retains_65_real_returned_buffers(self):
        with large_fixture() as case:
            case.make_receipts(self.writer)
            batch = case.batches[1]
            name = batch.fx.proposal_doc["files"][0]["path"]
            target = batch.fx.candidate / name
            original = target.read_bytes()
            changed = self._change_one_ascii_byte(original)
            self.assertEqual(len(original), len(changed))
            self.assertEqual(sum(a != b for a, b in zip(original, changed)), 1)
            write_private(target, changed, replace=True)
            report, measured, children = self._checked(case, "STALE")
            self.assertEqual(report["reason_codes"], ["CHILD_STALE"])
            self.assertEqual((report["content_reads"], report["verified_batches"]), (65, 1))
            self.assertEqual([child["status"] for child in children], ["MATCHED", "STALE"])
            self.assertEqual([child["content_reads"] for child in children], [64, 1])
            self.assertEqual(measured["lengths"], [70000] * 65)
            self.assertEqual(measured["bytes"], 4550000)
            self.assertEqual(measured["paths"][-1], name)
            self.assertEqual(target.read_bytes(), changed)

    def test_late_earlier_candidate_change_retains_129_buffers_and_findings(self):
        with large_fixture(screened=True, finding=True) as case:
            case.make_receipts(self.writer)
            findings = [{"batch_id": batch.id, **row} for batch in case.batches
                        for row in child_result(batch)["findings"]]
            self.assertTrue(findings)
            first = case.batches[0].fx
            target = first.candidate / first.proposal_doc["files"][0]["path"]
            original = target.read_bytes()
            changed = self._change_one_ascii_byte(original)
            mutations = []

            def after_child(count, result):
                self.assertEqual(result["status"], "MATCHED")
                if count == 2:
                    write_private(target, changed, replace=True)
                    mutations.append(count)

            report, measured, children = self._checked(case, "STALE", after_child=after_child,
                                                       permitted_changes=(target,))
            self.assertEqual(mutations, [2])
            self.assertEqual(report["reason_codes"], ["CANDIDATE_CHANGED"])
            self.assertEqual((report["content_reads"], report["verified_batches"]), (129, 2))
            self.assertEqual([child["status"] for child in children], ["MATCHED", "MATCHED"])
            self.assertEqual(measured["lengths"], [70000] * 129)
            self.assertEqual(measured["bytes"], 9030000)
            self.assertEqual(report["findings"], findings)
            self.assertEqual(report["text_review"], "REVIEW")
            self.assertEqual(target.read_bytes(), changed)
            self.assertEqual(len(original), len(changed))


if __name__ == "__main__":
    unittest.main()
