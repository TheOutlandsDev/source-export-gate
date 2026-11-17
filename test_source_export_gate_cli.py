"""Actual isolated CLI invocations over invented private fixtures only.

This module never imports the product. A reviewed runner must authorize the
Python subprocesses before executing these tests. No Git, provider, real source
family, real private-term file or held runtime is used.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager


SCRIPT = Path(__file__).absolute().with_name("source_export_gate.py")
TRUSTED_SCANNER = (Path(__file__).absolute().parent / "vendor/preupload_check.py")
SCANNER_SHA256 = "f1c70a7edae1ccad69e78fa18c03d708eabdf4f72e3b20f11add585551d53ff5"
FAMILIES = ("code-atlas", "java-python-kits", "coding-agent-methods", "agent-workbench",
            "wow-rebuild", "game-tools-ott", "workflow-lab", "blueprint-methods")
RESULT_KEYS = {"format", "eligibility", "reason_codes", "family", "proposed_files", "observed_files",
               "content_reads", "scanner_called", "text_review", "findings", "publication_status",
               "publication_authorized", "export_performed", "destination_verified", "git_metadata_reviewed", "bindings"}
SUMMARY_KEYS = (RESULT_KEYS - {"findings", "bindings"}) | {"finding_count"}
RECEIPT_FILES = {"CLAIM.json", "result.json", "REVIEW.md", "REVIEW.txt", "COMPLETE.json"}
SOURCE_BYTES = b"# SYNTHETIC_CANDIDATE_CONTENT_47: invented portable source only.\n"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode()


def write_private(path, raw, replace=False):
    missing = []
    parent = path.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
    flags = os.O_WRONLY | os.O_NOFOLLOW | (os.O_TRUNC if replace else os.O_CREAT | os.O_EXCL)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(raw)
    path.chmod(0o600)


def snapshot(root):
    """Do not follow links or open FIFOs in deliberately unsafe fixtures."""
    if not root.exists() and not root.is_symlink():
        return None
    rows = {}
    def walk(path):
        info = path.lstat()
        row = [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink]
        if stat.S_ISREG(info.st_mode):
            raw = path.read_bytes()
            row += [len(raw), digest(raw)]
        elif stat.S_ISLNK(info.st_mode):
            row.append(os.readlink(path))
        rows[str(path.relative_to(root))] = tuple(row)
        if stat.S_ISDIR(info.st_mode):
            for child in sorted(path.iterdir()):
                walk(child)
    walk(root)
    return rows


class Fixture:
    def __init__(self, root, family="agent-workbench", files=None, kind="source", synthetic=False):
        self.root = root
        self.candidate = root / "candidate"
        self.candidate.mkdir(mode=0o700)
        self.proposal = root / "proposal.json"
        self.review = root / "review.json"
        self.terms = root / "fictional-terms.json"
        self.receipt = root / "receipt"
        self.extra_inputs = []
        raw_files = {"invented_module_47.py": SOURCE_BYTES} if files is None else files
        rows = []
        for name, raw in sorted(raw_files.items()):
            write_private(self.candidate / name, raw)
            rows.append({"path": name, "sha256": digest(raw), "bytes": len(raw),
                         "artifact_kind": kind, "synthetic_fixture": synthetic})
        self.proposal_doc = {"format": "outlands-source-export-proposal-v1", "family": family, "files": rows}
        write_private(self.proposal, canonical(self.proposal_doc))
        self.review_doc = {"format": "outlands-source-export-review-v1", "family": family,
                           "proposal_sha256": digest(self.proposal.read_bytes()), "publication_authorized": False,
                           "files": [{"path": row["path"], "sha256": row["sha256"], "artifact_kind": row["artifact_kind"],
                                      "decision": "eligible", "source_authority": "reviewed", "ownership": "reviewed",
                                      "confidentiality": "reviewed", "rights": "reviewed", "notices": "preserved"}
                                     for row in rows]}
        write_private(self.review, canonical(self.review_doc))
        write_private(self.terms, canonical({"schema_version": 1, "terms": ["FICTIONAL_REVIEW_MARKER_47"]}))

    def save_proposal(self, rebind=False):
        write_private(self.proposal, canonical(self.proposal_doc), replace=True)
        if rebind:
            self.review_doc["proposal_sha256"] = digest(self.proposal.read_bytes())
            self.save_review()

    def save_review(self):
        write_private(self.review, canonical(self.review_doc), replace=True)

    def prepare_scanner(self):
        """Copy only pinned trusted test code; never alter the legacy tool."""
        raw = TRUSTED_SCANNER.read_bytes()
        if digest(raw) != SCANNER_SHA256:
            raise AssertionError("trusted scanner fixture pin mismatch")
        scanner = self.root / "pinned-text-scanner.py"
        write_private(scanner, raw)
        if scanner.read_bytes() != raw or digest(scanner.read_bytes()) != SCANNER_SHA256:
            raise AssertionError("private scanner fixture copy mismatch")
        self.extra_inputs.append(scanner)
        return scanner


@contextmanager
def fixture(**kwargs):
    with tempfile.TemporaryDirectory(prefix="invented-source-export-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        yield Fixture(root, **kwargs)


class SourceExportGateCliTests(unittest.TestCase):
    def flags(self, value):
        self.assertEqual(value["publication_status"], "HELD")
        for field in ("publication_authorized", "export_performed", "destination_verified", "git_metadata_reviewed"):
            self.assertIs(value[field], False)

    def validate_summary(self, value):
        self.assertEqual(set(value), SUMMARY_KEYS)
        self.assertEqual(value["format"], "outlands-source-export-cli-v2")
        self.assertIn(value["eligibility"], ("ELIGIBLE_FOR_TEXT_REVIEW", "HOLD", "REFUSED"))
        self.assertTrue(value["family"] is None or value["family"] in FAMILIES)
        self.assertIn(value["text_review"], ("NOT_RUN", "PASS", "REVIEW"))
        self.assertIs(type(value["scanner_called"]), bool)
        self.assertIs(type(value["reason_codes"]), list)
        for key in ("proposed_files", "observed_files", "content_reads", "finding_count"):
            self.assertIs(type(value[key]), int)
            self.assertGreaterEqual(value[key], 0)
        self.assertTrue(all(type(code) is str and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code)
                            for code in value["reason_codes"]))
        self.flags(value)

    def invoke(self, fx, expected_exit, *, receipt=None, proposal=None, review=None,
               scanner=None, terms=None, expect_receipt=True, extra_args=None):
        receipt = fx.receipt if receipt is None else receipt
        proposal = fx.proposal if proposal is None else proposal
        review = fx.review if review is None else review
        inputs = [fx.candidate, fx.proposal, fx.review, fx.terms, *fx.extra_inputs]
        before = {str(path): snapshot(path) for path in inputs}
        root_before = snapshot(fx.root)
        command = [sys.executable, "-I", "-B", str(SCRIPT), "--candidate", str(fx.candidate),
                   "--proposal", str(proposal), "--review", str(review), "--receipt", str(receipt)]
        command += ["--eligibility-only"] if scanner is None else ["--scanner", str(scanner), "--private-terms", str(terms)]
        command += [] if extra_args is None else extra_args
        completed = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=10,
                                   cwd=fx.root, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1"})
        self.assertEqual(completed.returncode, expected_exit)
        self.assertEqual(completed.stderr, b"")
        self.assertLessEqual(len(completed.stdout), 262144)
        self.assertEqual(len(completed.stdout.splitlines()), 1)
        self.assertNotIn(str(fx.root).encode(), completed.stdout)
        self.assertNotIn(str(SCRIPT).encode(), completed.stdout)
        self.assertNotIn(SOURCE_BYTES.strip(), completed.stdout)
        for marker in (b"/synthetic/invented-owner-47", b"INVENTED_PRIVATE_NOTE_MUST_NOT_ECHO", b"INVENTED_DO_NOT_ECHO"):
            self.assertNotIn(marker, completed.stdout)
        result = json.loads(completed.stdout)
        self.validate_summary(result)
        self.assertEqual({str(path): snapshot(path) for path in inputs}, before)
        after = snapshot(fx.root)
        if expect_receipt:
            info = receipt.lstat()
            self.assertTrue(stat.S_ISDIR(info.st_mode))
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)
            self.assertEqual(info.st_uid, os.getuid())
            self.assertEqual({p.name for p in receipt.iterdir()}, RECEIPT_FILES)
            self.assertEqual(set(after) - set(root_before), {str(receipt.relative_to(fx.root)),
                             *(str((receipt / name).relative_to(fx.root)) for name in RECEIPT_FILES)})
            for path in receipt.iterdir():
                info = path.lstat()
                self.assertTrue(stat.S_ISREG(info.st_mode))
                self.assertEqual((stat.S_IMODE(info.st_mode), info.st_uid, info.st_nlink), (0o600, os.getuid(), 1))
                self.assertNotIn(SOURCE_BYTES.strip(), path.read_bytes())
            private = json.loads((receipt / "result.json").read_bytes())
            self.assertEqual(set(private), RESULT_KEYS)
            self.assertEqual(private["format"], "outlands-source-export-result-v2")
            self.assertTrue(private["bindings"] is None or type(private["bindings"]) is dict)
            if private["eligibility"] != "ELIGIBLE_FOR_TEXT_REVIEW":
                self.assertIsNone(private["bindings"])
            self.assertIs(type(private["findings"]), list)
            for finding in private["findings"]:
                self.assertEqual(set(finding), {"path", "check"})
                self.assertFalse(finding["path"].startswith(("/", "\\")))
                self.assertRegex(finding["check"], r"^[A-Z][A-Z0-9_]{0,63}$")
            summary = {key: item for key, item in private.items() if key not in {"findings", "bindings"}}
            summary.update(format="outlands-source-export-cli-v2", finding_count=len(private["findings"]))
            self.assertEqual(result, summary)
            self.flags(private)
            self.assertEqual(json.loads((receipt / "CLAIM.json").read_bytes()), {
                "format": "outlands-source-export-claim-v2", "publication_authorized": False, "export_performed": False})
            self.assertEqual((receipt / "REVIEW.md").read_bytes(), (receipt / "REVIEW.txt").read_bytes())
            self.assertEqual(json.loads((receipt / "COMPLETE.json").read_bytes()), {
                "format": "outlands-source-export-complete-v1", "files": {
                    name: digest((receipt / name).read_bytes()) for name in RECEIPT_FILES - {"COMPLETE.json"}}})
        else:
            self.assertEqual(after, root_before)
        return result

    def blocked(self, value, *, reads=0, eligibility="HOLD"):
        self.assertEqual(value["eligibility"], eligibility)
        self.assertEqual(value["content_reads"], reads)
        self.assertIs(value["scanner_called"], False)
        self.assertEqual(value["text_review"], "NOT_RUN")
        self.assertEqual(value["finding_count"], 0)
        self.assertTrue(value["reason_codes"])

    def test_all_eight_family_labels_require_and_accept_explicit_review(self):
        for family in FAMILIES:
            with self.subTest(family=family), fixture(family=family) as fx:
                result = self.invoke(fx, 0)
                self.assertEqual(result["family"], family)
                self.assertEqual(result["eligibility"], "ELIGIBLE_FOR_TEXT_REVIEW")
                self.assertEqual((result["proposed_files"], result["observed_files"], result["content_reads"]), (1, 1, 1))
                self.assertEqual(result["reason_codes"], [])
                self.assertEqual(result["text_review"], "NOT_RUN")

    def test_reviewed_notice_build_source_and_synthetic_example_remain_possible(self):
        for name, kind, synthetic in (("NOTICE.txt", "notice", False), ("Dockerfile", "source", False),
                                      ("guide.md", "documentation", False), ("examples/invented.json", "synthetic_example", True)):
            with self.subTest(kind=kind), fixture(files={name: b"Invented reusable example.\n"}, kind=kind, synthetic=synthetic) as fx:
                self.assertEqual(self.invoke(fx, 0)["eligibility"], "ELIGIBLE_FOR_TEXT_REVIEW")

    def test_synthetic_flag_cannot_override_ineligible_artifact_classes(self):
        kinds = ("log", "runtime_record", "configuration", "credential", "database", "backup", "archive",
                 "patch", "git_metadata", "model_data", "employer_material", "client_material", "unknown")
        for kind in kinds:
            with self.subTest(kind=kind), fixture(kind=kind, synthetic=True) as fx:
                self.blocked(self.invoke(fx, 1))

    def test_source_mislabels_do_not_override_paths_suffixes_or_runtime_names(self):
        paths = ("runtime/item.json", "logs/plain.txt", "data/module.py", "backups/module.py", "exports/module.py",
                 "runs/module.py", "credentials/item.txt", "secrets/item.txt", "cache/module.py", ".git/HEAD",
                 ".github/workflows/qa.yml", "plain.LOG", "change.DIFF", ".env.example", "result.json")
        for name in paths:
            with self.subTest(path=name), fixture(files={name: b"Invented bland bytes.\n"}, synthetic=True) as fx:
                self.blocked(self.invoke(fx, 1))

    def test_env_suffix_and_sqlite_companions_hold_before_content_or_scanner(self):
        paths = ("app.env", "APP.ENV.local", "cache.sqlite-wal", "cache.sqlite-shm", "cache.sqlite-journal",
                 "db.sqlite3-wal", "copy.sqlite.backup", ".sqlite-wal")
        for name in paths:
            with self.subTest(path=name), fixture(files={name: b"Invented bland bytes.\n"}, kind="source", synthetic=True) as fx:
                result = self.invoke(fx, 1, scanner=fx.root / "absent-scanner.py", terms=fx.root / "absent-terms.json")
                self.blocked(result)
                self.assertEqual(result["reason_codes"], ["ARTIFACT_INELIGIBLE"])

    def test_synthetic_example_requires_true_declaration(self):
        with fixture(kind="synthetic_example", synthetic=False) as fx:
            self.blocked(self.invoke(fx, 1))

    def test_pending_unknown_and_excluded_review_assertions_stay_hold(self):
        changes = [(key, "pending") for key in ("source_authority", "ownership", "confidentiality", "rights", "notices")]
        changes += [("decision", "excluded"), ("confidentiality", "unknown")]
        for key, value in changes:
            with self.subTest(field=key), fixture() as fx:
                fx.review_doc["files"][0][key] = value
                fx.save_review()
                self.blocked(self.invoke(fx, 1))

    def test_validly_typed_review_binding_family_or_class_conflicts_stay_hold(self):
        for change in ("raw-proposal", "family", "hash", "kind", "paths"):
            with self.subTest(change=change), fixture() as fx:
                if change == "raw-proposal":
                    write_private(fx.proposal, fx.proposal.read_bytes() + b"\n", replace=True)
                elif change == "family":
                    fx.review_doc["family"] = "code-atlas"
                elif change == "hash":
                    fx.review_doc["files"][0]["sha256"] = "0" * 64
                elif change == "kind":
                    fx.review_doc["files"][0]["artifact_kind"] = "documentation"
                else:
                    fx.review_doc["files"][0]["path"] = "other.py"
                fx.save_review()
                self.blocked(self.invoke(fx, 1))

    def test_missing_extra_or_arbitrary_review_fields_refuse(self):
        for change in ("missing-rights", "extra-note", "wrong-status", "publish-true"):
            with self.subTest(change=change), fixture() as fx:
                if change == "missing-rights":
                    del fx.review_doc["files"][0]["rights"]
                elif change == "extra-note":
                    fx.review_doc["files"][0]["private_note"] = "INVENTED_PRIVATE_NOTE_MUST_NOT_ECHO"
                elif change == "wrong-status":
                    fx.review_doc["files"][0]["ownership"] = "automatically-cleared"
                else:
                    fx.review_doc["publication_authorized"] = True
                fx.save_review()
                result = self.invoke(fx, 2)
                self.blocked(result, eligibility="REFUSED")

    def test_malformed_json_utf8_duplicate_keys_and_constants_emit_finite_refusal(self):
        invalid = [b"{", b"\xff", b"[]", b"null", b'{"format":"a","format":"b"}',
                   b'{"private":"/synthetic/invented-owner-47/DO_NOT_ECHO","v":NaN}', b" " * 262145]
        for target in ("proposal", "review"):
            for index, raw in enumerate(invalid):
                with self.subTest(target=target, case=index), fixture() as fx:
                    write_private(getattr(fx, target), raw, replace=True)
                    self.blocked(self.invoke(fx, 2), eligibility="REFUSED")

    def test_bool_sizes_unknown_classes_and_extra_proposal_fields_refuse(self):
        for change in ("bool-size", "unknown-kind", "unknown-family", "extra-field", "over-file-limit"):
            with self.subTest(change=change), fixture() as fx:
                if change == "bool-size":
                    fx.proposal_doc["files"][0]["bytes"] = True
                elif change == "unknown-kind":
                    fx.proposal_doc["files"][0]["artifact_kind"] = "trust-me"
                elif change == "unknown-family":
                    fx.proposal_doc["family"] = "arbitrary-private-family"
                elif change == "extra-field":
                    fx.proposal_doc["files"][0]["note"] = "INVENTED_DO_NOT_ECHO"
                else:
                    fx.proposal_doc["files"][0]["bytes"] = 2000001
                fx.save_proposal(rebind=True)
                self.blocked(self.invoke(fx, 2), eligibility="REFUSED")

    def test_proposal_total_bound_is_checked_without_large_candidate_reads(self):
        with fixture(files={"part%d.py" % n: b"# invented\n" for n in range(5)}) as fx:
            for row in fx.proposal_doc["files"]:
                row["bytes"] = 2000000
            fx.save_proposal(rebind=True)
            self.blocked(self.invoke(fx, 2), eligibility="REFUSED")

    def test_traversal_backslash_absolute_and_empty_segments_refuse(self):
        for name in ("../outside.py", "a//b.py", "a\\b.py", "./module.py", "/synthetic/invented-owner-47/private.py"):
            with self.subTest(path=name), fixture() as fx:
                fx.proposal_doc["files"][0]["path"] = name
                fx.save_proposal(rebind=True)
                self.blocked(self.invoke(fx, 2), eligibility="REFUSED")

    def test_extra_missing_or_unexpected_empty_directories_block_before_content(self):
        for change in ("extra", "missing", "empty-dir"):
            with self.subTest(change=change), fixture() as fx:
                if change == "extra":
                    write_private(fx.candidate / "unexpected.py", b"# invented extra\n")
                elif change == "missing":
                    (fx.candidate / "invented_module_47.py").unlink()
                else:
                    (fx.candidate / "unused").mkdir(mode=0o700)
                self.blocked(self.invoke(fx, 1))

    def test_changed_hash_or_size_holds_and_never_reaches_scanner(self):
        for same_size in (True, False):
            with self.subTest(same_size=same_size), fixture() as fx:
                original = fx.candidate / "invented_module_47.py"
                changed = b"X" * len(SOURCE_BYTES) if same_size else b"X"
                write_private(original, changed, replace=True)
                self.blocked(self.invoke(fx, 1), reads=1 if same_size else 0)

    def test_binary_or_nul_inputs_are_not_text_eligible(self):
        for raw in (b"\xff", b"invented\x00bytes"):
            with self.subTest(raw_length=len(raw)), fixture(files={"module.py": raw}) as fx:
                self.blocked(self.invoke(fx, 1), reads=1)

    def test_symlink_hardlink_and_fifo_are_never_followed_or_read(self):
        for kind in ("symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind), fixture() as fx:
                target = fx.root / "outside-sentinel.py"
                write_private(target, SOURCE_BYTES)
                fx.extra_inputs.append(target)
                member = fx.candidate / "invented_module_47.py"
                member.unlink()
                if kind == "symlink":
                    member.symlink_to(target)
                elif kind == "hardlink":
                    os.link(target, member)
                else:
                    os.mkfifo(member, 0o600)
                self.blocked(self.invoke(fx, 1))

    def test_candidate_and_control_permission_guards_remain_distinct(self):
        for target in ("file", "directory", "review"):
            with self.subTest(target=target), fixture(files={"nested/module.py": SOURCE_BYTES}) as fx:
                if target == "file":
                    (fx.candidate / "nested/module.py").chmod(0o640)
                elif target == "directory":
                    (fx.candidate / "nested").chmod(0o750)
                else:
                    fx.review.chmod(0o640)
                self.blocked(self.invoke(fx, 2 if target == "review" else 1), eligibility="REFUSED" if target == "review" else "HOLD")

    def test_controls_inside_candidate_are_refused_without_content_read(self):
        with fixture() as fx:
            control = fx.candidate / "proposal.json"
            write_private(control, fx.proposal.read_bytes())
            self.blocked(self.invoke(fx, 2, proposal=control), eligibility="REFUSED")

    def test_existing_receipt_is_never_adopted_overwritten_or_removed(self):
        with fixture() as fx:
            self.invoke(fx, 0)
            before = snapshot(fx.receipt)
            result = self.invoke(fx, 2, expect_receipt=False)
            self.blocked(result, eligibility="REFUSED")
            self.assertEqual(snapshot(fx.receipt), before)

    def test_existing_receipt_file_or_symlink_is_not_overwritten(self):
        for kind in ("file", "symlink"):
            with self.subTest(kind=kind), fixture() as fx:
                if kind == "file":
                    write_private(fx.receipt, b"Invented receipt sentinel: preserve exactly.\n")
                else:
                    target = fx.root / "outside-receipt-target"
                    target.mkdir(mode=0o700)
                    write_private(target / "sentinel.txt", b"Invented outside sentinel.\n")
                    fx.receipt.symlink_to(target, target_is_directory=True)
                self.blocked(self.invoke(fx, 2, expect_receipt=False), eligibility="REFUSED")

    def test_receipt_inside_candidate_or_containing_input_paths_is_refused(self):
        for mode in ("candidate", "contains-inputs"):
            with self.subTest(mode=mode), fixture() as fx:
                receipt = fx.candidate / "receipt" if mode == "candidate" else fx.root / "uncreated-input-parent"
                proposal = fx.proposal if mode == "candidate" else receipt / "proposal.json"
                review = fx.review if mode == "candidate" else receipt / "review.json"
                self.blocked(self.invoke(fx, 2, receipt=receipt, proposal=proposal, review=review, expect_receipt=False), eligibility="REFUSED")

    def test_nonprivate_receipt_parent_is_refused_without_output_creation(self):
        with fixture() as fx:
            parent = fx.root / "nonprivate-parent"
            parent.mkdir(mode=0o755)
            parent.chmod(0o755)
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o755)
            self.blocked(self.invoke(fx, 2, receipt=parent / "receipt", expect_receipt=False), eligibility="REFUSED")

    def test_cli_invalid_arguments_are_json_refusals_without_echoing_values(self):
        with fixture() as fx:
            self.blocked(self.invoke(fx, 2, extra_args=["--invented-unknown-option", str(fx.root / "DO_NOT_ECHO")], expect_receipt=False), eligibility="REFUSED")

    def test_pinned_scanner_accepts_clean_captured_text_without_staging(self):
        with fixture() as fx:
            scanner = fx.prepare_scanner()
            result = self.invoke(fx, 0, scanner=scanner, terms=fx.terms)
            self.assertEqual((result["eligibility"], result["text_review"], result["finding_count"]), ("ELIGIBLE_FOR_TEXT_REVIEW", "PASS", 0))
            self.assertIs(result["scanner_called"], True)
            self.assertEqual(result["content_reads"], 1)

    def test_fake_private_marker_produces_private_findings_but_redacted_stdout(self):
        marker = b"FICTIONAL_REVIEW_MARKER_47"
        with fixture(files={"invented_module_47.py": b"# " + marker + b"\n"}) as fx:
            scanner = fx.prepare_scanner()
            result = self.invoke(fx, 1, scanner=scanner, terms=fx.terms)
            self.assertEqual((result["eligibility"], result["text_review"], result["finding_count"]), ("ELIGIBLE_FOR_TEXT_REVIEW", "REVIEW", 1))
            private = json.loads((fx.receipt / "result.json").read_bytes())
            self.assertEqual(private["findings"], [{"path": "invented_module_47.py", "check": "PRIVATE_TERM"}])
            self.assertNotIn(marker.decode(), json.dumps(result))
            self.assertNotIn("invented_module_47.py", json.dumps(result))

    def test_eligibility_hold_never_loads_missing_scanner_or_terms(self):
        with fixture(kind="runtime_record", synthetic=True) as fx:
            self.blocked(self.invoke(fx, 1, scanner=fx.root / "absent-scanner.py", terms=fx.root / "absent-terms.json"))

    def test_unpinned_scanner_is_refused_before_execution(self):
        with fixture() as fx:
            fake = fx.root / "invented-untrusted-scanner.py"
            write_private(fake, b"raise AssertionError('invented scanner must not execute')\n")
            fx.extra_inputs.append(fake)
            result = self.invoke(fx, 2, scanner=fake, terms=fx.terms)
            self.assertEqual(result["eligibility"], "REFUSED")
            self.assertEqual(result["reason_codes"], ["SCANNER_PIN"])
            self.assertIs(result["scanner_called"], False)

    def test_real_private_terms_are_unneeded_and_invented_terms_must_be_private(self):
        with fixture() as fx:
            scanner = fx.prepare_scanner()
            fx.terms.chmod(0o644)
            result = self.invoke(fx, 2, scanner=scanner, terms=fx.terms)
            self.assertEqual(result["eligibility"], "REFUSED")
            self.assertEqual(result["reason_codes"], ["PRIVATE_FILE"])
            self.assertEqual(result["content_reads"], 1)
            self.assertIs(result["scanner_called"], False)


if __name__ == "__main__":
    unittest.main()
