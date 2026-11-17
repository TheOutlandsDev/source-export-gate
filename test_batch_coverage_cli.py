"""Real isolated CLIs over invented text; no product imports in this module.

Execution needs the reviewed runner's exact three-script subprocess allowlist.
The shared fixture is also used by the in-process, externally guarded suite.
"""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

from test_source_export_gate_cli import (Fixture, FAMILIES, RECEIPT_FILES,
                                         canonical, digest, snapshot, write_private)


HERE = Path(__file__).absolute().parent
WRITER = HERE / "source_export_gate.py"
VERIFIER = HERE / "verify_source_export_receipt.py"
COVERAGE = HERE / "verify_batch_coverage.py"
REPORT_FIELDS = {"format", "status", "reason_codes", "family", "declared_files", "covered_files",
                 "batch_count", "verified_batches", "content_reads", "text_review", "scanner_called",
                 "findings", "batches", "bindings", "publication_status", "publication_authorized",
                 "export_performed", "destination_verified", "git_metadata_reviewed"}
SUMMARY_FIELDS = (REPORT_FIELDS - {"findings", "batches", "bindings"}) | {"finding_count"}
MARKER = "FICTIONAL_REVIEW_MARKER_47"


def invented_files(count=129, finding=False):
    files = {}
    for index in range(count):
        java = index % 2 == 1
        name = "src/" + ("Invented%04d.java" if java else "invented%04d.py") % index
        raw = ("// Invented Java text; never compiled.\n" if java
               else "# Invented Python text; never executed.\n").encode()
        files[name] = raw
    if finding:
        name = sorted(files)[-1]
        files[name] += ("// " + MARKER + "\n").encode()
    return files


def child_result(batch):
    return json.loads((batch.fx.receipt / "result.json").read_bytes())


def reseal(receipt):
    write_private(receipt / "COMPLETE.json", canonical({
        "format": "outlands-source-export-complete-v1",
        "files": {name: digest((receipt / name).read_bytes())
                  for name in sorted(RECEIPT_FILES - {"COMPLETE.json"})}}), replace=True)


def rewrite_result(batch, mutate):
    value = child_result(batch)
    mutate(value)
    write_private(batch.fx.receipt / "result.json", canonical(value), replace=True)
    reseal(batch.fx.receipt)


def legacy_receipt(batch):
    value = child_result(batch)
    value.pop("bindings")
    value["format"] = "outlands-source-export-result-v1"
    write_private(batch.fx.receipt / "result.json", canonical(value), replace=True)
    write_private(batch.fx.receipt / "CLAIM.json", canonical({
        "format": "outlands-source-export-claim-v1", "publication_authorized": False,
        "export_performed": False}), replace=True)
    (batch.fx.receipt / "COMPLETE.json").unlink()


class BatchFixture:
    def __init__(self, root, *, files=None, counts=(128, 1), family="agent-workbench",
                 screened=False, finding=False):
        self.root = root
        self.files = invented_files(sum(counts), finding=finding) if files is None else files
        if sum(counts) != len(self.files):
            raise AssertionError("invented partition must cover every declared file")
        self.batches = []
        names, offset = sorted(self.files), 0
        for index, count in enumerate(counts):
            directory = root / ("batch%02d" % index)
            directory.mkdir(mode=0o700)
            fx = Fixture(directory, family=family,
                         files={name: self.files[name] for name in names[offset:offset + count]})
            offset += count
            scanner = fx.prepare_scanner() if screened else None
            self.batches.append(SimpleNamespace(id="batch%02d" % index, fx=fx, scanner=scanner,
                                                 terms=fx.terms if screened else None))
        self.manifest = root / "full-manifest.json"
        self.plan = root / "batch-plan.json"
        rows = [row for batch in self.batches for row in batch.fx.proposal_doc["files"]]
        self.manifest_doc = {"format": "outlands-batch-coverage-manifest-v1", "family": family,
                             "review_mode": "screened" if screened else "eligibility_only",
                             "publication_authorized": False,
                             "files": sorted(rows, key=lambda row: row["path"])}
        write_private(self.manifest, canonical(self.manifest_doc))
        self.plan_doc = {"format": "outlands-batch-coverage-plan-v1",
                         "manifest_sha256": digest(self.manifest.read_bytes()), "batches": [
            {"id": batch.id, "candidate": str(batch.fx.candidate), "proposal": str(batch.fx.proposal),
             "review": str(batch.fx.review), "receipt": str(batch.fx.receipt),
             "scanner": None if batch.scanner is None else str(batch.scanner),
             "private_terms": None if batch.terms is None else str(batch.terms)} for batch in self.batches]}
        write_private(self.plan, canonical(self.plan_doc))

    def save_manifest(self, rebind=True):
        write_private(self.manifest, canonical(self.manifest_doc), replace=True)
        if rebind:
            self.plan_doc["manifest_sha256"] = digest(self.manifest.read_bytes())
            self.save_plan()

    def save_plan(self):
        write_private(self.plan, canonical(self.plan_doc), replace=True)

    def make_receipts(self, writer):
        for batch in self.batches:
            writer(batch)


@contextmanager
def batch_fixture(**kwargs):
    with tempfile.TemporaryDirectory(prefix="invented-batch-coverage-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        yield BatchFixture(root, **kwargs)


def writer_args(batch):
    fx = batch.fx
    args = ["--candidate", str(fx.candidate), "--proposal", str(fx.proposal),
            "--review", str(fx.review), "--receipt", str(fx.receipt)]
    return args + (["--eligibility-only"] if batch.scanner is None else
                   ["--scanner", str(batch.scanner), "--private-terms", str(batch.terms)])


class BatchCoverageCliTests(unittest.TestCase):
    def run_script(self, script, args, root):
        completed = subprocess.run([sys.executable, "-I", "-B", str(script), *args],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=20, check=False, cwd=root,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1"})
        self.assertEqual(completed.stderr, b"")
        self.assertLessEqual(len(completed.stdout), 262144)
        self.assertEqual(len(completed.stdout.splitlines()), 1)
        return completed, json.loads(completed.stdout)

    def writer(self, batch):
        process, value = self.run_script(WRITER, writer_args(batch), batch.fx.root)
        self.assertIn(process.returncode, (0, 1))
        self.assertTrue((batch.fx.receipt / "COMPLETE.json").is_file())
        self.assertIs(value["publication_authorized"], False)

    def invoke(self, case, status, code, *, args=None):
        before = snapshot(case.root)
        process, value = self.run_script(COVERAGE,
            ["--manifest", str(case.manifest), "--plan", str(case.plan)] if args is None else args, case.root)
        self.assertEqual(snapshot(case.root), before)
        self.assertEqual(process.returncode, code)
        self.assertEqual(set(value), SUMMARY_FIELDS)
        self.assertEqual(value["format"], "outlands-batch-coverage-cli-v1")
        self.assertEqual(value["status"], status)
        self.assertEqual(value["publication_status"], "HELD")
        for key in ("publication_authorized", "export_performed", "destination_verified", "git_metadata_reviewed", "scanner_called"):
            self.assertIs(value[key], False)
        for key in ("declared_files", "covered_files", "batch_count", "verified_batches", "content_reads", "finding_count"):
            self.assertIs(type(value[key]), int)
            self.assertGreaterEqual(value[key], 0)
        self.assertTrue(all(type(reason) is str and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", reason)
                            for reason in value["reason_codes"]))
        for forbidden in (str(case.root).encode(), MARKER.encode(), b"DO_NOT_ECHO", digest(case.manifest.read_bytes()).encode()):
            self.assertNotIn(forbidden, process.stdout)
        self.assertIsNone(re.search(rb"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", process.stdout))
        return value

    def test_129_python_java_eligibility_only_union_and_individual_verifier(self):
        with batch_fixture() as case:
            case.make_receipts(self.writer)
            value = self.invoke(case, "MATCHED", 0)
            self.assertEqual((value["declared_files"], value["covered_files"], value["content_reads"]), (129, 129, 129))
            self.assertEqual((value["batch_count"], value["verified_batches"], value["text_review"]), (2, 2, "NOT_RUN"))
            batch = case.batches[1]
            before = snapshot(case.root)
            process, child = self.run_script(VERIFIER, ["--candidate", str(batch.fx.candidate),
                "--proposal", str(batch.fx.proposal), "--review", str(batch.fx.review),
                "--receipt", str(batch.fx.receipt)], case.root)
            self.assertEqual((process.returncode, child["status"]), (0, "MATCHED"))
            self.assertEqual(snapshot(case.root), before)

    def test_129_screened_clean_and_prior_findings_have_distinct_exit_codes(self):
        for finding in (False, True):
            with self.subTest(finding=finding), batch_fixture(screened=True, finding=finding) as case:
                case.make_receipts(self.writer)
                value = self.invoke(case, "MATCHED", 1 if finding else 0)
                self.assertEqual(value["text_review"], "REVIEW" if finding else "PASS")
                self.assertEqual(value["content_reads"], 129)
                self.assertEqual(value["finding_count"] > 0, finding)

    def test_missing_extra_changed_and_class_rows_hold_before_content_reads(self):
        for change in ("missing", "extra", "hash", "bytes", "class"):
            with self.subTest(change=change), batch_fixture(counts=(1, 1)) as case:
                case.make_receipts(self.writer)
                rows = case.manifest_doc["files"]
                if change == "missing": rows.pop()
                elif change == "extra": rows.append(dict(rows[-1], path="z_extra.py"))
                elif change == "hash": rows[0]["sha256"] = "0" * 64
                elif change == "bytes": rows[0]["bytes"] += 1
                else: rows[0]["artifact_kind"] = "documentation"
                case.save_manifest()
                self.assertEqual(self.invoke(case, "HOLD", 1)["content_reads"], 0)

    def test_duplicate_coverage_is_not_counted_twice(self):
        with batch_fixture(counts=(1, 1)) as case:
            first = case.batches[0].fx.proposal_doc["files"][0]
            second = case.batches[1].fx
            old = second.proposal_doc["files"][0]["path"]
            (second.candidate / old).unlink()
            write_private(second.candidate / first["path"], case.files[first["path"]])
            second.proposal_doc["files"] = [dict(first)]
            second.review_doc["files"][0].update(path=first["path"], sha256=first["sha256"])
            second.save_proposal(rebind=True)
            case.make_receipts(self.writer)
            self.assertEqual(self.invoke(case, "HOLD", 1)["content_reads"], 0)

    def test_family_and_semantic_screen_mode_mismatches_hold(self):
        for change in ("family", "mode"):
            with self.subTest(change=change), batch_fixture(counts=(1, 1)) as case:
                case.make_receipts(self.writer)
                if change == "family":
                    rewrite_result(case.batches[1], lambda value: value.update(family="code-atlas"))
                else:
                    case.manifest_doc["review_mode"] = "screened"
                    for batch, row in zip(case.batches, case.plan_doc["batches"]):
                        row["scanner"] = str(batch.fx.prepare_scanner())
                        row["private_terms"] = str(batch.fx.terms)
                    case.save_manifest()
                self.assertEqual(self.invoke(case, "HOLD", 1)["content_reads"], 0)

    def test_partial_and_exact_legacy_receipts_are_unverifiable_without_repair(self):
        for legacy in (False, True):
            with self.subTest(legacy=legacy), batch_fixture(counts=(1, 1)) as case:
                case.make_receipts(self.writer)
                if legacy: legacy_receipt(case.batches[0])
                else: (case.batches[0].fx.receipt / "COMPLETE.json").unlink()
                self.assertEqual(self.invoke(case, "UNVERIFIABLE", 1)["content_reads"], 0)

    def test_current_candidate_bytes_modes_and_membership_become_stale(self):
        for change in ("bytes", "mode", "extra"):
            with self.subTest(change=change), batch_fixture(counts=(1, 1)) as case:
                case.make_receipts(self.writer)
                batch = case.batches[0]
                member = batch.fx.candidate / batch.fx.proposal_doc["files"][0]["path"]
                if change == "bytes": write_private(member, member.read_bytes().replace(b"Invented", b"Changed!"), replace=True)
                elif change == "mode": member.chmod(0o644)
                else: write_private(batch.fx.candidate / "extra.py", b"# Invented extra\n")
                value = self.invoke(case, "STALE", 1)
                self.assertEqual(value["verified_batches"], 0)

    def test_control_raw_pin_drift_is_stale(self):
        for target in ("proposal", "review"):
            with self.subTest(target=target), batch_fixture(counts=(1, 1)) as case:
                case.make_receipts(self.writer)
                path = getattr(case.batches[0].fx, target)
                write_private(path, path.read_bytes() + b" ", replace=True)
                self.assertEqual(self.invoke(case, "STALE", 1)["content_reads"], 0)

    def test_unsafe_receipt_and_overlapping_roots_refuse_without_reads(self):
        for change in ("file-mode", "root-overlap", "same-receipt"):
            with self.subTest(change=change), batch_fixture(counts=(1, 1)) as case:
                case.make_receipts(self.writer)
                if change == "file-mode": (case.batches[0].fx.receipt / "result.json").chmod(0o644)
                elif change == "root-overlap": case.plan_doc["batches"][1]["candidate"] = str(case.batches[0].fx.candidate)
                else: case.plan_doc["batches"][1]["receipt"] = str(case.batches[0].fx.receipt)
                case.save_plan()
                self.assertEqual(self.invoke(case, "REFUSED", 2)["content_reads"], 0)

    def test_screen_terms_and_policy_mismatch_do_not_rerun_screen(self):
        for change in ("terms", "policy"):
            with self.subTest(change=change), batch_fixture(counts=(1, 1), screened=True) as case:
                case.make_receipts(self.writer)
                def mutate(value):
                    binding = value["bindings"]
                    if change == "terms": binding["screen"]["private_terms_sha256"] = "0" * 64
                    else: binding["policy"]["engine_sha256"] = "0" * 64
                rewrite_result(case.batches[1], mutate)
                self.assertEqual(self.invoke(case, "HOLD", 1)["content_reads"], 0)

    def test_ineligible_lexical_path_is_held_even_without_child_receipts(self):
        with batch_fixture(counts=(1, 1)) as case:
            case.manifest_doc["files"][0]["path"] = "private.env"
            case.manifest_doc["files"].sort(key=lambda row: row["path"])
            case.save_manifest()
            self.assertEqual(self.invoke(case, "HOLD", 1)["content_reads"], 0)

    def test_malformed_arguments_metadata_and_private_values_are_redacted(self):
        for change in ("args", "duplicate-json", "unknown-field", "raw-binding"):
            with self.subTest(change=change), batch_fixture(counts=(1, 1)) as case:
                if change == "args":
                    self.invoke(case, "REFUSED", 2, args=["--manifest", "/invented/private/DO_NOT_ECHO", "--pl", str(case.plan)])
                elif change == "duplicate-json":
                    write_private(case.plan, b'{"format":"DO_NOT_ECHO","format":"duplicate"}\n', replace=True)
                    self.invoke(case, "REFUSED", 2)
                elif change == "unknown-field":
                    case.plan_doc["private_note"] = "DO_NOT_ECHO"
                    case.save_plan()
                    self.invoke(case, "REFUSED", 2)
                else:
                    write_private(case.manifest, case.manifest.read_bytes() + b" ", replace=True)
                    self.assertEqual(self.invoke(case, "HOLD", 1)["content_reads"], 0)


if __name__ == "__main__":
    unittest.main()
