"""Fresh private packet fixtures and actual fixed isolated CLI regressions.

No product is imported here. Helpers are plain functions, shared by the library
suite without importing a TestCase. All text and terms are newly invented.
"""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import unittest

from test_large_candidate_cli import (MARKER, WRITER, canonical, child_result,
    digest, large_fixture, snapshot, write_private, writer_args)


SCRIPT = Path(__file__).absolute().with_name("coverage_receipts.py")
PACKET_FILES = {"CLAIM.json", "record.json", "REVIEW.md", "REVIEW.txt", "COMPLETE.json"}
SAVE_FIELDS = {"format", "status", "reason_codes", "coverage_status", "text_review", "finding_count",
    "content_reads", "scanner_called", "publication_status", "publication_authorized", "export_performed",
    "destination_verified", "git_metadata_reviewed"}
VERIFY_FIELDS = (SAVE_FIELDS - {"coverage_status"}) | {"integrity", "freshness", "saved_status"}


@contextmanager
def coverage_fixture(writer, *, large=False, screened=False, finding=False, held=False):
    with large_fixture(screened=screened, finding=finding,
                       counts=(64, 65) if large else (1, 1), size=70000 if large else 256) as case:
        case.make_receipts(writer)
        case.packet = case.root / "coverage-packet"
        if held:
            # A valid manifest with a different known family yields a real HOLD,
            # while the original child observations/findings remain available.
            case.manifest_doc["family"] = "code-atlas"
            case.save_manifest()
        yield case


def packet_record(case):
    return json.loads((case.packet / "record.json").read_bytes())


def reseal_packet(packet):
    write_private(packet / "COMPLETE.json", canonical({
        "format": "outlands-private-coverage-complete-v1", "files": {
            name: digest((packet / name).read_bytes())
            for name in sorted(PACKET_FILES - {"COMPLETE.json"})}}), replace=True)


def rewrite_record(case, mutate):
    value = packet_record(case)
    mutate(value)
    write_private(case.packet / "record.json", canonical(value), replace=True)
    reseal_packet(case.packet)


def actual_bytes(case):
    """Independent fixture-byte check, not an old six-label measurement call."""
    expected = {row["path"]: row for row in case.manifest_doc["files"]}
    observed, totals = {}, []
    for batch in case.batches:
        total = 0
        for row in batch.fx.proposal_doc["files"]:
            name = row["path"]
            path = batch.fx.candidate / name
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os.getuid() or info.st_nlink != 1 or name in observed):
                raise AssertionError("unsafe invented fixture bytes")
            raw = path.read_bytes()
            raw.decode("utf-8")
            if b"\x00" in raw or len(raw) != expected[name]["bytes"] or digest(raw) != expected[name]["sha256"]:
                raise AssertionError("invented fixture differs from its declared bytes")
            observed[name] = len(raw)
            total += len(raw)
        totals.append(total)
    if set(observed) != set(expected):
        raise AssertionError("incomplete invented byte coverage")
    return observed, totals


def cli_args(operation, case, *, receipt=None):
    return [operation, "--manifest", str(case.manifest), "--plan", str(case.plan),
            "--receipt", str(case.packet if receipt is None else receipt)]


class CoverageReceiptsCliTests(unittest.TestCase):
    def run_script(self, script, args, root):
        completed = subprocess.run([sys.executable, "-I", "-B", str(script), *args],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=False, cwd=root,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1"})
        self.assertEqual(completed.stderr, b"")
        self.assertLessEqual(len(completed.stdout), 262144)
        self.assertEqual(len(completed.stdout.splitlines()), 1)
        self.assertNotIn(str(root).encode(), completed.stdout)
        self.assertNotIn(MARKER.encode(), completed.stdout)
        self.assertNotIn(b"INVENTED_DO_NOT_ECHO", completed.stdout)
        self.assertIsNone(re.search(rb"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", completed.stdout))
        return completed, json.loads(completed.stdout)

    def writer(self, batch):
        process, value = self.run_script(WRITER, writer_args(batch), batch.fx.root)
        self.assertIn(process.returncode, (0, 1))
        self.assertEqual(value["eligibility"], "ELIGIBLE_FOR_TEXT_REVIEW")
        self.assertTrue((batch.fx.receipt / "COMPLETE.json").is_file())

    def validate(self, value, operation):
        self.assertEqual(set(value), SAVE_FIELDS if operation == "save" else VERIFY_FIELDS)
        self.assertEqual(value["format"], "outlands-private-coverage-save-v1" if operation == "save"
                         else "outlands-private-coverage-verification-v1")
        self.assertEqual(value["publication_status"], "HELD")
        for key in ("scanner_called", "publication_authorized", "export_performed", "destination_verified", "git_metadata_reviewed"):
            self.assertIs(value[key], False)
        for key in ("finding_count", "content_reads"):
            self.assertIs(type(value[key]), int)
            self.assertGreaterEqual(value[key], 0)
        self.assertTrue(all(type(code) is str and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code)
                            for code in value["reason_codes"]))

    def invoke(self, case, operation, status, exit_code, *, receipt=None, args=None, creates=False):
        before = snapshot(case.root)
        process, value = self.run_script(SCRIPT, cli_args(operation, case, receipt=receipt) if args is None else args, case.root)
        self.assertEqual(process.returncode, exit_code)
        self.validate(value, operation)
        self.assertEqual(value["status"], status)
        after = snapshot(case.root)
        if creates:
            self.assertEqual(set(after) - set(before), {"coverage-packet", *("coverage-packet/" + name for name in PACKET_FILES)})
            for name, row in before.items():
                self.assertEqual(after[name][:4] if name == "." else after[name], row[:4] if name == "." else row)
            self.assertEqual(stat.S_IMODE(case.packet.stat().st_mode), 0o700)
            for path in case.packet.iterdir():
                info = path.lstat()
                self.assertEqual((stat.S_IMODE(info.st_mode), info.st_uid, info.st_nlink), (0o600, os.getuid(), 1))
                self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual((case.packet / "REVIEW.md").read_bytes(), (case.packet / "REVIEW.txt").read_bytes())
        else:
            self.assertEqual(after, before)
        return value

    def test_actual_9030000_byte_clean_and_findings_packets_save_then_verify_readonly(self):
        for finding in (False, True):
            with self.subTest(finding=finding), coverage_fixture(self.writer, large=True, screened=True, finding=finding) as case:
                observed, totals = actual_bytes(case)
                self.assertEqual((len(observed), set(observed.values()), totals), (129, {70000}, [4480000, 4550000]))
                saved = self.invoke(case, "save", "SAVED", 1 if finding else 0, creates=True)
                self.assertEqual((saved["coverage_status"], saved["content_reads"], saved["text_review"]),
                                 ("MATCHED", 129, "REVIEW" if finding else "PASS"))
                record = packet_record(case)
                self.assertEqual(record["report"]["findings"], [{"batch_id": batch.id, **row}
                    for batch in case.batches for row in child_result(batch)["findings"]])
                verified = self.invoke(case, "verify", "MATCHED", 1 if finding else 0)
                self.assertEqual((verified["integrity"], verified["freshness"], verified["saved_status"], verified["content_reads"]),
                                 ("MATCHED", "MATCHED", "MATCHED", 129))
                self.assertEqual(verified["finding_count"], saved["finding_count"])
                actual_bytes(case)

    def test_eligibility_only_packet_never_implies_text_screen(self):
        with coverage_fixture(self.writer) as case:
            self.invoke(case, "save", "SAVED", 0, creates=True)
            value = self.invoke(case, "verify", "MATCHED", 0)
            self.assertEqual((value["text_review"], value["finding_count"], value["content_reads"]), ("NOT_RUN", 0, 2))

    def test_saved_hold_with_findings_is_not_promoted_or_rechecked(self):
        with coverage_fixture(self.writer, screened=True, finding=True, held=True) as case:
            saved = self.invoke(case, "save", "SAVED", 1, creates=True)
            self.assertEqual(saved["coverage_status"], "HOLD")
            self.assertGreater(saved["finding_count"], 0)
            value = self.invoke(case, "verify", "UNVERIFIABLE", 1)
            self.assertEqual((value["saved_status"], value["text_review"], value["finding_count"], value["content_reads"]),
                             ("HOLD", "REVIEW", saved["finding_count"], 0))

    def test_actual_large_changed_candidate_retains_65_read_attempts(self):
        with coverage_fixture(self.writer, large=True) as case:
            self.invoke(case, "save", "SAVED", 0, creates=True)
            batch = case.batches[1]
            member = batch.fx.candidate / batch.fx.proposal_doc["files"][0]["path"]
            raw = member.read_bytes()
            changed = raw.replace(b"Invented", b"Modified", 1)
            self.assertEqual(len(changed), len(raw))
            self.assertNotEqual(changed, raw)
            write_private(member, changed, replace=True)
            value = self.invoke(case, "verify", "STALE", 1)
            self.assertEqual((value["saved_status"], value["content_reads"]), ("MATCHED", 65))

    def test_current_manifest_and_plan_raw_changes_stay_stale_before_member_reads(self):
        for target in ("manifest", "plan"):
            with self.subTest(target=target), coverage_fixture(self.writer) as case:
                self.invoke(case, "save", "SAVED", 0, creates=True)
                path = getattr(case, target)
                write_private(path, path.read_bytes() + b" ", replace=True)
                value = self.invoke(case, "verify", "STALE", 1)
                self.assertEqual(value["content_reads"], 0)

    def test_missing_completion_foreign_and_unsafe_packets_remain_unqualified(self):
        for change in ("complete", "record", "foreign", "extra", "file-mode", "symlink"):
            with self.subTest(change=change), coverage_fixture(self.writer) as case:
                self.invoke(case, "save", "SAVED", 0, creates=True)
                if change in {"complete", "record"}: (case.packet / ("COMPLETE.json" if change == "complete" else "record.json")).unlink()
                elif change == "foreign":
                    write_private(case.packet / "CLAIM.json", canonical({"format": "outlands-source-export-claim-v2",
                        "publication_authorized": False, "export_performed": False}), replace=True)
                    reseal_packet(case.packet)
                elif change == "extra": write_private(case.packet / "extra.json", b"{}\n")
                elif change == "file-mode": (case.packet / "record.json").chmod(0o644)
                else:
                    member = case.packet / "record.json"
                    outside = case.root / "invented-record.json"
                    write_private(outside, member.read_bytes())
                    member.unlink()
                    member.symlink_to(outside)
                value = self.invoke(case, "verify", "UNVERIFIABLE" if change in {"complete", "record"} else "REFUSED",
                                    1 if change in {"complete", "record"} else 2)
                self.assertEqual(value["content_reads"], 0)

    def test_coherently_resealed_report_contradictions_refuse_before_content(self):
        for change in ("bool", "authority", "counter", "input-binding", "findings"):
            with self.subTest(change=change), coverage_fixture(self.writer) as case:
                self.invoke(case, "save", "SAVED", 0, creates=True)
                def mutate(record):
                    report = record["report"]
                    if change == "bool": report["declared_files"] = True
                    elif change == "authority": report["publication_authorized"] = True
                    elif change == "counter": report["verified_batches"] = 0
                    elif change == "input-binding": record["inputs"]["manifest_sha256"] = "0" * 64
                    else: report["batches"][0]["finding_count"] = 1
                rewrite_record(case, mutate)
                self.assertEqual(self.invoke(case, "verify", "REFUSED", 2)["content_reads"], 0)

    def test_existing_packet_save_does_not_overwrite_or_adopt(self):
        with coverage_fixture(self.writer) as case:
            self.invoke(case, "save", "SAVED", 0, creates=True)
            self.invoke(case, "save", "REFUSED", 2)

    def test_unsafe_destination_and_parent_refuse_without_any_new_packet(self):
        for change in ("inside-candidate", "ancestor", "parent-mode", "symlink"):
            with self.subTest(change=change), coverage_fixture(self.writer) as case:
                if change == "inside-candidate": target = case.batches[0].fx.candidate / "new-packet"
                elif change == "ancestor": target = case.root
                elif change == "parent-mode":
                    parent = case.root / "public-parent"
                    parent.mkdir(mode=0o700)
                    parent.chmod(0o755)
                    target = parent / "new-packet"
                else:
                    target = case.packet
                    target.symlink_to(case.batches[0].fx.receipt, target_is_directory=True)
                self.assertEqual(self.invoke(case, "save", "REFUSED", 2, receipt=target)["content_reads"], 0)

    def test_malformed_controls_and_cli_arguments_are_finite_and_redacted(self):
        for operation in ("save", "verify"):
            for change in ("metadata", "arguments", "abbreviation"):
                with self.subTest(operation=operation, change=change), coverage_fixture(self.writer) as case:
                    args = None
                    if change == "metadata":
                        if operation == "verify":
                            self.invoke(case, "save", "SAVED", 0, creates=True)
                        write_private(case.manifest, b'{"private":"INVENTED_DO_NOT_ECHO"}\n', replace=True)
                    elif change == "arguments":
                        args = [operation, "--manifest", "/invented/private/INVENTED_DO_NOT_ECHO"]
                    else:
                        args = [operation, "--man", str(case.manifest), "--plan", str(case.plan), "--receipt", str(case.packet)]
                    self.assertEqual(self.invoke(case, operation, "REFUSED", 2, args=args)["content_reads"], 0)


if __name__ == "__main__":
    unittest.main()
