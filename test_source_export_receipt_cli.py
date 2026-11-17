"""Real isolated CLI checks over invented receipt fixtures; no product imports."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest

from test_source_export_gate_cli import (SCRIPT, SOURCE_BYTES, canonical, digest, fixture,
                                        snapshot, write_private)


VERIFY = SCRIPT.with_name("verify_source_export_receipt.py")
SUMMARY_FIELDS = {"format", "status", "reason_codes", "content_reads", "scanner_called", "publication_status",
                  "publication_authorized", "export_performed", "destination_verified", "git_metadata_reviewed"}
MEMBERS = {"CLAIM.json", "REVIEW.md", "REVIEW.txt", "result.json"}


def reseal(receipt):
    value = {"format": "outlands-source-export-complete-v1", "files": {
        name: digest((receipt / name).read_bytes()) for name in sorted(MEMBERS)}}
    write_private(receipt / "COMPLETE.json", canonical(value), replace=True)


class SourceExportReceiptCliTests(unittest.TestCase):
    def process(self, command, cwd):
        allowed = {(sys.executable, "-I", "-B", str(SCRIPT)), (sys.executable, "-I", "-B", str(VERIFY))}
        self.assertIn(tuple(command[:4]), allowed)
        return subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=10, check=False,
                              cwd=cwd, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1"})

    def create(self, fx, *, screen=False, held=False):
        if held:
            fx.review_doc["files"][0]["confidentiality"] = "unknown"
            fx.save_review()
        command = [sys.executable, "-I", "-B", str(SCRIPT), "--candidate", str(fx.candidate),
                   "--proposal", str(fx.proposal), "--review", str(fx.review), "--receipt", str(fx.receipt)]
        fx.screen_scanner = None
        if screen:
            fx.screen_scanner = fx.prepare_scanner()
            command += ["--scanner", str(fx.screen_scanner), "--private-terms", str(fx.terms)]
        else:
            command += ["--eligibility-only"]
        completed = self.process(command, fx.root)
        self.assertIn(completed.returncode, (0, 1))
        self.assertEqual(completed.stderr, b"")
        summary = json.loads(completed.stdout)
        self.assertEqual(summary["format"], "outlands-source-export-cli-v2")
        self.assertNotIn("bindings", summary)
        self.assertNotIn("findings", summary)
        self.assertEqual({p.name for p in fx.receipt.iterdir()}, MEMBERS | {"COMPLETE.json"})
        self.assertEqual(json.loads((fx.receipt / "COMPLETE.json").read_bytes()), {
            "format": "outlands-source-export-complete-v1", "files": {
                name: digest((fx.receipt / name).read_bytes()) for name in MEMBERS}})

    def verify(self, fx, status, exit_code, *, reason=None, reads=None, screen=False,
               scanner=None, terms=None, extra_args=None):
        before = snapshot(fx.root)
        command = [sys.executable, "-I", "-B", str(VERIFY), "--candidate", str(fx.candidate),
                   "--proposal", str(fx.proposal), "--review", str(fx.review), "--receipt", str(fx.receipt)]
        if screen:
            scanner, terms = fx.screen_scanner, fx.terms
        if scanner is not None:
            command += ["--scanner", str(scanner)]
        if terms is not None:
            command += ["--private-terms", str(terms)]
        command += [] if extra_args is None else extra_args
        completed = self.process(command, fx.root)
        self.assertEqual(completed.returncode, exit_code)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(len(completed.stdout.splitlines()), 1)
        self.assertLessEqual(len(completed.stdout), 2048)
        self.assertNotIn(str(fx.root).encode(), completed.stdout)
        self.assertNotIn(b"FICTIONAL_REVIEW_MARKER_47", completed.stdout)
        self.assertNotIn(b"invented_module_47.py", completed.stdout)
        self.assertIsNone(re.search(rb"[0-9a-f]{64}", completed.stdout))
        value = json.loads(completed.stdout)
        self.assertEqual(set(value), SUMMARY_FIELDS)
        self.assertEqual(value["format"], "outlands-source-export-verification-v1")
        self.assertEqual(value["status"], status)
        self.assertIs(type(value["content_reads"]), int)
        self.assertIs(value["scanner_called"], False)
        self.assertEqual(value["publication_status"], "HELD")
        for field in ("publication_authorized", "export_performed", "destination_verified", "git_metadata_reviewed"):
            self.assertIs(value[field], False)
        if reason is not None:
            self.assertEqual(value["reason_codes"], [reason])
        if reads is not None:
            self.assertEqual(value["content_reads"], reads)
        self.assertEqual(snapshot(fx.root), before)
        return value

    def test_new_python_java_receipt_matches_readonly_on_repeated_verification(self):
        files = {"python/invented.py": SOURCE_BYTES, "java/Invented.java": b"// Invented Java text; never compiled.\n"}
        with fixture(files=files) as fx:
            self.create(fx)
            self.assertEqual(self.verify(fx, "MATCHED", 0, reads=2)["reason_codes"], [])
            self.verify(fx, "MATCHED", 0, reads=2)

    def test_proposal_or_review_raw_format_drift_is_stale(self):
        for target in ("proposal", "review"):
            with self.subTest(target=target), fixture() as fx:
                self.create(fx)
                path = getattr(fx, target)
                write_private(path, path.read_bytes() + b" ", replace=True)
                self.verify(fx, "STALE", 1, reason="INPUT_CHANGED", reads=0)

    def test_changed_reviewed_classification_does_not_refresh_receipt(self):
        with fixture() as fx:
            self.create(fx)
            fx.proposal_doc["files"][0]["artifact_kind"] = "documentation"
            fx.review_doc["files"][0]["artifact_kind"] = "documentation"
            fx.save_proposal(rebind=True)
            self.verify(fx, "STALE", 1, reason="INPUT_CHANGED", reads=0)

    def test_current_bytes_membership_and_modes_are_checked(self):
        for change in ("bytes", "extra", "directory", "mode"):
            with self.subTest(change=change), fixture() as fx:
                self.create(fx)
                member = fx.candidate / "invented_module_47.py"
                if change == "bytes": write_private(member, b"X" * len(SOURCE_BYTES), replace=True)
                elif change == "extra": write_private(fx.candidate / "extra.py", b"# invented\n")
                elif change == "directory": (fx.candidate / "extra").mkdir(mode=0o700)
                else: member.chmod(0o644)
                self.verify(fx, "STALE", 1, reason="CANDIDATE_CHANGED", reads=1 if change == "bytes" else 0)

    def test_screen_pass_and_screen_review_match_without_changing_saved_findings(self):
        for raw, expected_text in ((SOURCE_BYTES, "PASS"), (b"# FICTIONAL_REVIEW_MARKER_47\n", "REVIEW")):
            with self.subTest(text=expected_text), fixture(files={"invented_module_47.py": raw}) as fx:
                self.create(fx, screen=True)
                saved = (fx.receipt / "result.json").read_bytes()
                self.assertEqual(json.loads(saved)["text_review"], expected_text)
                self.verify(fx, "MATCHED", 0, reads=1, screen=True)
                self.assertEqual((fx.receipt / "result.json").read_bytes(), saved)

    def test_changed_scanner_and_terms_are_not_executed_or_reassessed(self):
        for target in ("scanner", "terms"):
            with self.subTest(target=target), fixture() as fx:
                self.create(fx, screen=True)
                path = fx.screen_scanner if target == "scanner" else fx.terms
                raw = b"raise AssertionError('invented scanner must not run during verification')\n" if target == "scanner" else path.read_bytes() + b" "
                write_private(path, raw, replace=True)
                self.verify(fx, "STALE", 1, reason="CONTROL_CHANGED", reads=0, screen=True)

    def test_partial_five_file_receipt_is_unverifiable_without_repair(self):
        for missing in ("COMPLETE.json", "result.json", "REVIEW.txt"):
            with self.subTest(missing=missing), fixture() as fx:
                self.create(fx)
                (fx.receipt / missing).unlink()
                self.verify(fx, "UNVERIFIABLE", 1, reason="RECEIPT_INCOMPLETE", reads=0)

    def test_exact_v1_four_file_receipt_is_legacy_not_upgraded(self):
        with fixture() as fx:
            self.create(fx)
            result = json.loads((fx.receipt / "result.json").read_bytes())
            result.pop("bindings")
            result["format"] = "outlands-source-export-result-v1"
            write_private(fx.receipt / "result.json", canonical(result), replace=True)
            write_private(fx.receipt / "CLAIM.json", canonical({"format": "outlands-source-export-claim-v1",
                          "publication_authorized": False, "export_performed": False}), replace=True)
            (fx.receipt / "COMPLETE.json").unlink()
            self.verify(fx, "UNVERIFIABLE", 1, reason="LEGACY_RECEIPT", reads=0)

    def test_resealed_inconsistent_results_and_bindings_are_not_authenticated(self):
        for change in ("counter", "authority", "bound-bytes"):
            with self.subTest(change=change), fixture() as fx:
                self.create(fx)
                result = json.loads((fx.receipt / "result.json").read_bytes())
                if change == "counter": result["content_reads"] = True
                elif change == "authority": result["publication_authorized"] = True
                else: result["bindings"]["files"][0]["bytes"] += 1
                write_private(fx.receipt / "result.json", canonical(result), replace=True)
                reseal(fx.receipt)
                self.verify(fx, "REFUSED", 2, reason="RECEIPT_INVALID", reads=0)

    def test_unsafe_extra_receipt_artifact_or_checksum_mismatch_refuses(self):
        for change in ("mode", "extra", "checksum"):
            with self.subTest(change=change), fixture() as fx:
                self.create(fx)
                if change == "mode": (fx.receipt / "result.json").chmod(0o644)
                elif change == "extra": write_private(fx.receipt / "unexpected.json", b"{}\n")
                else:
                    path = fx.receipt / "result.json"
                    write_private(path, path.read_bytes() + b" ", replace=True)
                self.verify(fx, "REFUSED", 2, reason="RECEIPT_INVALID", reads=0)

    def test_completed_hold_with_null_bindings_is_not_matchable(self):
        with fixture() as fx:
            self.create(fx, held=True)
            self.verify(fx, "UNVERIFIABLE", 1, reason="ASSESSMENT_INCOMPLETE", reads=0)

    def test_missing_control_and_invalid_cli_flags_have_finite_private_refusals(self):
        with fixture() as fx:
            self.create(fx)
            fx.review.unlink()
            self.verify(fx, "UNVERIFIABLE", 1, reason="INPUT_UNAVAILABLE", reads=0)
        with fixture() as fx:
            self.create(fx)
            self.verify(fx, "REFUSED", 2, reason="CLI_ARGUMENTS", reads=0,
                        extra_args=["--eligibility-only", str(fx.root / "DO_NOT_ECHO")])

    def test_screen_arguments_must_match_the_recorded_observation(self):
        with fixture() as fx:
            self.create(fx, screen=True)
            self.verify(fx, "UNVERIFIABLE", 1, reason="SCANNER_REQUIRED", reads=0)
            self.verify(fx, "REFUSED", 2, reason="SCANNER_ARGUMENTS", reads=0, scanner=fx.screen_scanner)
        with fixture() as fx:
            self.create(fx)
            self.verify(fx, "REFUSED", 2, reason="SCANNER_ARGUMENTS", reads=0,
                        scanner=fx.root / "missing-scanner.py", terms=fx.root / "missing-terms.json")


if __name__ == "__main__":
    unittest.main()
