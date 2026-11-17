"""Unsigned receipt consistency over fresh invented trees; never a live audit."""

from contextlib import ExitStack, contextmanager, redirect_stdout
import copy
from io import StringIO
import json
import os
from pathlib import Path
import re
import unittest
from unittest.mock import patch

import source_export_gate as gate
import verify_source_export_receipt as verifier
from test_source_export_gate import (FAMILIES, INVENTED, canonical, digest, fixture,
                                     inventory_bytes, save_proposal, save_review, write_private)
from test_source_export_gate_cli import SCANNER_SHA256, TRUSTED_SCANNER


SUMMARY_FIELDS = {"format", "status", "reason_codes", "content_reads", "scanner_called", "publication_status",
                  "publication_authorized", "export_performed", "destination_verified", "git_metadata_reviewed"}
MEMBERS = {"CLAIM.json", "REVIEW.md", "REVIEW.txt", "result.json"}


def reseal(receipt):
    """Invented coherent rewrite, to test invariants beyond mere checksums."""
    write_private(receipt / "COMPLETE.json", canonical({"format": "outlands-source-export-complete-v1",
                  "files": {name: digest((receipt / name).read_bytes()) for name in sorted(MEMBERS)}}))


def result_value(case):
    return json.loads((case.receipt / "result.json").read_bytes())


def rewrite_result(case, mutate):
    value = result_value(case)
    mutate(value)
    write_private(case.receipt / "result.json", canonical(value))
    reseal(case.receipt)


@contextmanager
def observation(*, screen=False, files=None, family=FAMILIES[0], held=False):
    with fixture(files=files, family=family) as case:
        case.receipt = case.root / "receipt"
        case.scanner = case.terms = None
        argv = ["--candidate", str(case.candidate), "--proposal", str(case.proposal_path),
                "--review", str(case.review_path), "--receipt", str(case.receipt)]
        if held:
            case.review["files"][0]["confidentiality"] = "unknown"
            save_review(case)
        if screen:
            raw = TRUSTED_SCANNER.read_bytes()
            if digest(raw) != SCANNER_SHA256:
                raise AssertionError("trusted synthetic scanner fixture pin mismatch")
            case.scanner, case.terms = case.metadata / "scanner.py", case.metadata / "terms.json"
            write_private(case.scanner, raw)
            write_private(case.terms, canonical({"schema_version": 1, "terms": ["FICTIONAL_RECEIPT_MARKER_47"]}))
            argv += ["--scanner", str(case.scanner), "--private-terms", str(case.terms)]
        else:
            argv += ["--eligibility-only"]
        with redirect_stdout(StringIO()):
            code = gate.main(argv)
        if code not in (0, 1) or not (case.receipt / "COMPLETE.json").is_file():
            raise AssertionError("synthetic writer fixture did not complete")
        yield case


class SourceExportReceiptTests(unittest.TestCase):
    def setUp(self):
        self.guards = ExitStack()
        self.addCleanup(self.guards.close)
        self.denied = []
        for target in ("socket.socket", "socket.create_connection", "subprocess.Popen", "subprocess.run",
                       "os.execve", "os.system", "os.posix_spawn", "os.posix_spawnp", "os.fork"):
            self.denied.append(self.guards.enter_context(patch(target, side_effect=AssertionError("external action forbidden"))))

    def tearDown(self):
        for denied in self.denied:
            denied.assert_not_called()

    def call(self, case, *, scanner=None, terms=None, zero_reads=False):
        with ExitStack() as stack:
            assessed = stack.enter_context(patch.object(verifier.gate, "assess", side_effect=AssertionError("verification reassessed")))
            screened = stack.enter_context(patch.object(verifier.gate, "_screen_snapshot", side_effect=AssertionError("verification reran screen")))
            member = None
            if zero_reads:
                member = stack.enter_context(patch.object(verifier.gate, "_read_member", side_effect=AssertionError("invalid evidence read candidate")))
            value = verifier.verify(case.candidate, case.proposal_path, case.review_path, case.receipt,
                                    scanner_path=scanner, private_terms_path=terms)
        assessed.assert_not_called()
        screened.assert_not_called()
        if member is not None:
            member.assert_not_called()
        self.assertEqual(set(value), SUMMARY_FIELDS)
        self.assertEqual(value["format"], "outlands-source-export-verification-v1")
        self.assertIn(value["status"], {"MATCHED", "STALE", "UNVERIFIABLE", "REFUSED"})
        self.assertIs(type(value["content_reads"]), int)
        self.assertIs(value["scanner_called"], False)
        self.assertEqual(value["publication_status"], "HELD")
        for key in ("publication_authorized", "export_performed", "destination_verified", "git_metadata_reviewed"):
            self.assertIs(value[key], False)
        self.assertNotIn(str(case.root), json.dumps(value))
        self.assertNotIn("FICTIONAL_RECEIPT_MARKER_47", json.dumps(value))
        self.assertTrue(all(type(code) is str and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code)
                            for code in value["reason_codes"]))
        return value

    def readonly(self, case, expected, reason=None, *, reads=None, scanner=None, terms=None):
        before = inventory_bytes(case.root)
        value = self.call(case, scanner=scanner, terms=terms, zero_reads=reads == 0)
        self.assertEqual(inventory_bytes(case.root), before)
        self.assertEqual(value["status"], expected)
        if reason is not None:
            self.assertEqual(value["reason_codes"], [reason])
        if reads is not None:
            self.assertEqual(value["content_reads"], reads)
        return value

    def test_bindings_pin_actual_raw_controls_bytes_classes_modes_and_directories(self):
        files = {"src/a.py": INVENTED, "java/Invented.java": b"// Invented text, never compiled.\n"}
        with observation(files=files) as case:
            bindings = result_value(case)["bindings"]
            self.assertEqual(set(bindings), {"format", "policy", "proposal_sha256", "review_sha256", "files", "directories", "screen"})
            self.assertEqual(bindings["format"], "outlands-source-export-bindings-v1")
            self.assertEqual(bindings["policy"], {"id": "outlands-source-export-policy-v02",
                             "engine_sha256": digest(Path(gate.__file__).read_bytes())})
            self.assertEqual(bindings["proposal_sha256"], digest(case.proposal_path.read_bytes()))
            self.assertEqual(bindings["review_sha256"], digest(case.review_path.read_bytes()))
            self.assertEqual(bindings["files"], [{"path": name, "sha256": digest(raw), "bytes": len(raw), "mode": "0600",
                             "artifact_kind": "source", "synthetic_fixture": False} for name, raw in sorted(files.items())])
            self.assertEqual(bindings["directories"], [{"path": name, "mode": "0700"} for name in ("", "java", "src")])
            self.assertIsNone(bindings["screen"])
            self.assertNotIn(str(case.root), json.dumps(bindings))
            self.readonly(case, "MATCHED", reads=2)

    def test_every_family_python_and_java_receipt_verifies_without_execution(self):
        for family in FAMILIES:
            with self.subTest(family=family), observation(family=family, files={"a.py": INVENTED, "B.java": b"// Invented Java\n"}) as case:
                value = self.readonly(case, "MATCHED", reads=2)
                self.assertEqual(value["reason_codes"], [])

    def test_screen_bindings_match_without_rerun_and_findings_remain_findings(self):
        for raw, text in ((INVENTED, "PASS"), (b"# FICTIONAL_RECEIPT_MARKER_47\n", "REVIEW")):
            with self.subTest(text=text), observation(screen=True, files={"src/example.py": raw}) as case:
                result = result_value(case)
                self.assertEqual(result["text_review"], text)
                self.assertEqual(result["bindings"]["screen"], {"scanner_sha256": SCANNER_SHA256,
                                 "private_terms_sha256": digest(case.terms.read_bytes())})
                old_findings = copy.deepcopy(result["findings"])
                self.readonly(case, "MATCHED", reads=1, scanner=case.scanner, terms=case.terms)
                self.assertEqual(result_value(case)["findings"], old_findings)

    def test_raw_proposal_or_review_formatting_changes_are_stale_before_candidate_read(self):
        for target in ("proposal_path", "review_path"):
            with self.subTest(target=target), observation() as case:
                path = getattr(case, target)
                write_private(path, path.read_bytes() + b" ")
                self.readonly(case, "STALE", "INPUT_CHANGED", reads=0)

    def test_changed_classification_and_rebound_review_do_not_reuse_old_observation(self):
        with observation() as case:
            case.proposal["files"][0]["artifact_kind"] = "documentation"
            case.review["files"][0]["artifact_kind"] = "documentation"
            save_proposal(case)
            self.readonly(case, "STALE", "INPUT_CHANGED", reads=0)

    def test_current_candidate_bytes_size_membership_and_directory_drift_are_stale(self):
        for change in ("bytes", "size", "extra", "missing", "directory", "file-mode", "directory-mode"):
            with self.subTest(change=change), observation() as case:
                member = case.candidate / "src/example.py"
                if change == "bytes": write_private(member, INVENTED.replace(b"7", b"8"))
                elif change == "size": write_private(member, b"# changed size\n")
                elif change == "extra": write_private(case.candidate / "extra.py", b"# invented extra\n")
                elif change == "missing": member.unlink()
                elif change == "directory": (case.candidate / "extra").mkdir(mode=0o700)
                elif change == "file-mode": member.chmod(0o644)
                else: (case.candidate / "src").chmod(0o755)
                self.readonly(case, "STALE", "CANDIDATE_CHANGED", reads=1 if change == "bytes" else 0)

    def test_recorded_policy_hash_change_is_stale_without_touching_engine(self):
        with observation() as case:
            rewrite_result(case, lambda result: result["bindings"]["policy"].update(engine_sha256="0" * 64))
            self.readonly(case, "STALE", "POLICY_CHANGED", reads=0)

    def test_screen_controls_are_only_hashed_and_changes_are_stale(self):
        for target in ("scanner", "terms"):
            with self.subTest(target=target), observation(screen=True) as case:
                path = getattr(case, target)
                write_private(path, path.read_bytes() + b"\n")
                self.readonly(case, "STALE", "CONTROL_CHANGED", reads=0, scanner=case.scanner, terms=case.terms)

    def test_required_missing_or_extraneous_scanner_arguments_cannot_match(self):
        with observation(screen=True) as case:
            self.readonly(case, "UNVERIFIABLE", "SCANNER_REQUIRED", reads=0)
            self.readonly(case, "REFUSED", "SCANNER_ARGUMENTS", reads=0, scanner=case.scanner)
        with observation() as case:
            self.readonly(case, "REFUSED", "SCANNER_ARGUMENTS", reads=0,
                          scanner=case.metadata / "absent.py", terms=case.metadata / "absent.json")

    def test_missing_current_controls_remain_unverifiable_not_reassessed(self):
        with observation() as case:
            case.review_path.unlink()
            self.readonly(case, "UNVERIFIABLE", "INPUT_UNAVAILABLE", reads=0)

    def test_completed_hold_with_null_bindings_is_unverifiable(self):
        with observation(held=True) as case:
            self.assertIsNone(result_value(case)["bindings"])
            self.readonly(case, "UNVERIFIABLE", "ASSESSMENT_INCOMPLETE", reads=0)

    def test_partial_receipt_members_stay_incomplete_and_are_not_repaired(self):
        for missing in ("COMPLETE.json", "result.json", "REVIEW.txt", "CLAIM.json"):
            with self.subTest(missing=missing), observation() as case:
                (case.receipt / missing).unlink()
                self.readonly(case, "UNVERIFIABLE", "RECEIPT_INCOMPLETE", reads=0)

    def test_exact_legacy_v1_four_file_receipt_is_unverifiable_without_upgrade(self):
        with observation() as case:
            result = result_value(case)
            result.pop("bindings")
            result["format"] = "outlands-source-export-result-v1"
            write_private(case.receipt / "result.json", canonical(result))
            write_private(case.receipt / "CLAIM.json", canonical({"format": "outlands-source-export-claim-v1",
                          "publication_authorized": False, "export_performed": False}))
            (case.receipt / "COMPLETE.json").unlink()
            self.readonly(case, "UNVERIFIABLE", "LEGACY_RECEIPT", reads=0)

    def test_raw_member_changes_are_rejected_before_candidate_reads(self):
        for name in MEMBERS:
            with self.subTest(member=name), observation() as case:
                path = case.receipt / name
                write_private(path, path.read_bytes() + b" ")
                self.readonly(case, "REFUSED", "RECEIPT_INVALID", reads=0)

    def test_extra_linked_special_and_nonprivate_receipt_members_refuse(self):
        for change in ("extra", "symlink", "hardlink", "fifo", "file-mode", "directory-mode"):
            with self.subTest(change=change), observation() as case:
                path = case.receipt / "result.json"
                if change == "extra": write_private(case.receipt / "extra.json", b"{}\n")
                elif change == "file-mode": path.chmod(0o644)
                elif change == "directory-mode": case.receipt.chmod(0o755)
                else:
                    outside = case.metadata / "invented-result.json"
                    write_private(outside, path.read_bytes())
                    path.unlink()
                    if change == "symlink": path.symlink_to(outside)
                    elif change == "hardlink": os.link(outside, path)
                    else: os.mkfifo(path, 0o600)
                self.readonly(case, "REFUSED", "RECEIPT_INVALID", reads=0)

    def test_coherently_resealed_result_invariant_contradictions_refuse(self):
        mutations = [lambda r: r.update(proposed_files=True), lambda r: r.update(observed_files=0),
                     lambda r: r.update(content_reads=0), lambda r: r.update(publication_authorized=True),
                     lambda r: r.update(text_review="PASS", scanner_called=False),
                     lambda r: r.update(family=None), lambda r: r.update(format="invented-result-format"),
                     lambda r: r.update(findings=[{"path": "src/example.py", "check": "PRIVATE_TERM"}])]
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index), observation() as case:
                rewrite_result(case, mutate)
                self.readonly(case, "REFUSED", "RECEIPT_INVALID", reads=0)

    def test_coherently_resealed_binding_declaration_conflicts_fail_before_reads(self):
        mutations = [lambda b: b["files"][0].update(sha256="0" * 64),
                     lambda b: b["files"][0].update(bytes=len(INVENTED) + 1),
                     lambda b: b["files"][0].update(artifact_kind="documentation"),
                     lambda b: b["files"][0].update(synthetic_fixture=True),
                     lambda b: b["files"][0].update(path="src/different.py")]
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index), observation() as case:
                rewrite_result(case, lambda result: mutate(result["bindings"]))
                self.readonly(case, "REFUSED", "RECEIPT_INVALID", reads=0)

    def test_malformed_binding_schema_modes_directories_and_screen_pin_refuse(self):
        mutations = [lambda b: b.update(format="invented-bindings"), lambda b: b.update(extra=False),
                     lambda b: b["policy"].update(id="invented-policy"),
                     lambda b: b["files"][0].update(mode="0644"),
                     lambda b: b["files"][0].update(bytes=True),
                     lambda b: b["directories"].append({"path": "extra", "mode": "0700"}),
                     lambda b: b.update(screen={"scanner_sha256": "0" * 64, "private_terms_sha256": "1" * 64})]
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index), observation() as case:
                rewrite_result(case, lambda result: mutate(result["bindings"]))
                self.readonly(case, "REFUSED", "RECEIPT_INVALID", reads=0)

    def test_malformed_completion_json_never_reads_candidate(self):
        for raw in (b"{", b"\xff", b'{"format":1,"format":2}', b'{"format":NaN}', b"{}\n"):
            with self.subTest(raw_length=len(raw)), observation() as case:
                write_private(case.receipt / "COMPLETE.json", raw)
                self.readonly(case, "REFUSED", "RECEIPT_INVALID", reads=0)

    def test_assessment_withholds_bindings_if_policy_changes_during_capture(self):
        with fixture() as case:
            original = gate._policy_snapshot
            count = 0
            def drift(**kwargs):
                nonlocal count
                count += 1
                pin, code_hash = original(**kwargs)
                return pin, code_hash if count == 1 else "0" * 64
            with patch.object(gate, "_policy_snapshot", side_effect=drift):
                result = gate.assess(case.candidate, case.proposal_path, case.review_path)
            self.assertEqual(result["eligibility"], "HOLD")
            self.assertIsNone(result["bindings"])
            self.assertGreaterEqual(count, 2)

    def test_policy_path_inside_candidate_is_refused_before_policy_or_member_read(self):
        with fixture() as case:
            with patch.object(gate, "__file__", str(case.candidate / "src/example.py")), \
                    patch.object(gate, "_policy_snapshot", side_effect=AssertionError("policy read before location guard")) as policy, \
                    patch.object(gate, "_read_member", side_effect=AssertionError("member read before location guard")) as member:
                result = gate.assess(case.candidate, case.proposal_path, case.review_path)
            self.assertEqual((result["eligibility"], result["reason_codes"], result["content_reads"]), ("REFUSED", ["POLICY_LOCATION"], 0))
            self.assertIsNone(result["bindings"])
            policy.assert_not_called()
            member.assert_not_called()
        with observation() as case:
            with patch.object(verifier.gate, "__file__", str(case.candidate / "src/example.py")), \
                    patch.object(verifier.gate, "_policy_snapshot", side_effect=AssertionError("verifier read policy before location guard")) as policy:
                self.readonly(case, "REFUSED", "INPUT_INVALID", reads=0)
            policy.assert_not_called()

    def test_candidate_mutation_during_final_policy_read_withholds_bindings(self):
        with fixture() as case:
            original = gate._policy_snapshot
            count = 0
            def drift(**kwargs):
                nonlocal count
                count += 1
                value = original(**kwargs)
                if count == 2:
                    write_private(case.candidate / "src/example.py", INVENTED.replace(b"7", b"8"))
                return value
            with patch.object(gate, "_policy_snapshot", side_effect=drift):
                result = gate.assess(case.candidate, case.proposal_path, case.review_path)
            self.assertEqual((result["eligibility"], result["reason_codes"]), ("HOLD", ["CANDIDATE_CHANGED"]))
            self.assertIsNone(result["bindings"])
            self.assertEqual(count, 2)

    def test_assessment_withholds_bindings_if_raw_inputs_change_after_capture(self):
        with fixture() as case:
            original = gate._read_member
            def drift(*args, **kwargs):
                raw = original(*args, **kwargs)
                write_private(case.review_path, case.review_path.read_bytes() + b" ")
                return raw
            with patch.object(gate, "_read_member", side_effect=drift):
                result = gate.assess(case.candidate, case.proposal_path, case.review_path)
            self.assertEqual(result["eligibility"], "HOLD")
            self.assertIsNone(result["bindings"])

    def test_late_input_change_is_stale_and_never_reruns_screen(self):
        with observation() as case:
            original = verifier.gate._read_member
            old_receipt = inventory_bytes(case.receipt)
            def drift(*args, **kwargs):
                raw = original(*args, **kwargs)
                write_private(case.review_path, case.review_path.read_bytes() + b" ")
                return raw
            with patch.object(verifier.gate, "_read_member", side_effect=drift):
                result = self.call(case)
            self.assertEqual((result["status"], result["reason_codes"]), ("STALE", ["INPUT_CHANGED"]))
            self.assertEqual(inventory_bytes(case.receipt), old_receipt)

    def test_late_coherent_receipt_change_cannot_match_initial_snapshot(self):
        with observation() as case:
            original = verifier.gate._read_member
            expected_after = None
            def drift(*args, **kwargs):
                nonlocal expected_after
                raw = original(*args, **kwargs)
                note = (case.receipt / "REVIEW.md").read_bytes() + b"\nInvented additional note.\n"
                write_private(case.receipt / "REVIEW.md", note)
                write_private(case.receipt / "REVIEW.txt", note)
                reseal(case.receipt)
                expected_after = inventory_bytes(case.root)
                return raw
            with patch.object(verifier.gate, "_read_member", side_effect=drift):
                result = self.call(case)
            self.assertEqual((result["status"], result["reason_codes"]), ("STALE", ["RECEIPT_CHANGED"]))
            self.assertEqual(inventory_bytes(case.root), expected_after)

    def test_final_receipt_read_detects_late_candidate_or_invalid_note_change(self):
        for change, reason in (("candidate", "CANDIDATE_CHANGED"), ("invalid-note", "RECEIPT_CHANGED")):
            with self.subTest(change=change), observation() as case:
                original = verifier._receipt_snapshot
                count = 0
                expected_after = None
                def drift(path):
                    nonlocal count, expected_after
                    count += 1
                    if count == 2 and change == "invalid-note":
                        write_private(case.receipt / "REVIEW.md", b"\xff")
                        write_private(case.receipt / "REVIEW.txt", b"\xff")
                        reseal(case.receipt)
                        expected_after = inventory_bytes(case.root)
                    value = original(path)
                    if count == 2 and change == "candidate":
                        write_private(case.candidate / "src/example.py", INVENTED.replace(b"7", b"8"))
                        expected_after = inventory_bytes(case.root)
                    return value
                with patch.object(verifier, "_receipt_snapshot", side_effect=drift):
                    result = self.call(case)
                self.assertEqual((result["status"], result["reason_codes"]), ("STALE", [reason]))
                self.assertEqual(count, 2)
                self.assertEqual(inventory_bytes(case.root), expected_after)


if __name__ == "__main__":
    unittest.main()
