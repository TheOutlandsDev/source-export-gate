"""Actual fixed CLIs and plain invented intake fixtures; no product imports.

Temporary fixture lifetime is inherited test behavior. Only two opt-in proof
records are retained by the reviewed qualification harness; no real input is used.
"""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest

from test_source_export_gate_cli import FAMILIES, canonical, digest, snapshot, write_private
from test_large_candidate_cli import sized_files


SCRIPT = Path(__file__).absolute().with_name("build_review_intake.py")
GATE = SCRIPT.with_name("source_export_gate.py")
OUTPUT_ORDER = ("CLAIM.json", "proposal.json", "review-draft.json", "CHECKLIST.md", "CHECKLIST.txt", "evidence-bindings.json", "INTAKE-COMPLETE.json")
PENDING_FIELDS = ("decision", "source_authority", "ownership", "confidentiality", "rights", "notices")
RESULT_FIELDS = {"format", "status", "reason_codes", "declared_files", "content_reads", "recheck_reads", "draft_created",
    "complete_written", "files_written", "publication_status", "publication_authorized", "export_performed",
    "destination_verified", "git_metadata_reviewed", "scanner_called", "bindings"}
SUMMARY_FIELDS = RESULT_FIELDS - {"bindings"}
PROOF_FIELDS = {"format", "label", "actual_file_count", "actual_total_bytes", "builder_status", "gate_eligibility",
    "gate_reason_codes", "gate_content_reads", "all_review_fields_pending", "complete_marker_verified",
    "publication_authorized", "export_performed", "source_map_sha256", "proposal_sha256", "review_sha256", "selection_sha256"}
DEFAULT_FILES = {
    "docs/guide.md": "# Invented guide — café, synthetic text only.\n".encode("utf-8"),
    "java/Invented.java": "// Invented Java — π, never compiled.\n".encode("utf-8"),
    "python/invented.py": "# Invented Python — naïve, never executed.\n".encode("utf-8"),
}


class IntakeFixture:
    def __init__(self, root, *, files=None, family="agent-workbench", kinds=None, synthetic=False):
        self.root = root
        self.candidate = root / "candidate"
        self.candidate.mkdir(mode=0o700)
        self.files = dict(DEFAULT_FILES if files is None else files)
        self.selection = root / "selection.json"
        self.output = root / "intake"
        self.proposal = self.output / "proposal.json"
        self.review = self.output / "review-draft.json"
        self.gate_receipt = root / "gate-receipt"
        rows = []
        for name, raw in sorted(self.files.items()):
            write_private(self.candidate / name, raw)
            kind = (kinds or {}).get(name, "documentation" if name.endswith(".md") else "source")
            rows.append({"path": name, "artifact_kind": kind, "synthetic_fixture": synthetic})
        self.selection_doc = {"format": "outlands-source-export-intake-selection-v1", "family": family, "files": rows}
        write_private(self.selection, canonical(self.selection_doc))

    def save_selection(self):
        write_private(self.selection, canonical(self.selection_doc), replace=True)


@contextmanager
def intake_fixture(**kwargs):
    with tempfile.TemporaryDirectory(prefix="invented-review-intake-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        yield IntakeFixture(root, **kwargs)


def complete_value(case):
    return json.loads((case.output / "INTAKE-COMPLETE.json").read_bytes())


def pending_proof(case, label, builder_result, gate_result):
    """Hash actual selected bytes and confirm pending metadata without approval."""
    if label not in {"unit-pending", "cli-pending"}:
        raise AssertionError("unknown private proof label")
    proposal_raw, review_raw = case.proposal.read_bytes(), case.review.read_bytes()
    proposal, review = json.loads(proposal_raw), json.loads(review_raw)
    rows = []
    for selected, record in zip(case.selection_doc["files"], proposal["files"]):
        path = case.candidate / selected["path"]
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.getuid() or info.st_nlink != 1):
            raise AssertionError("unsafe invented selected member")
        raw = path.read_bytes()
        raw.decode("utf-8")
        actual = {"path": selected["path"], "sha256": digest(raw), "bytes": len(raw)}
        if any(actual[key] != record[key] for key in actual) or b"\x00" in raw:
            raise AssertionError("proposal differs from selected bytes")
        rows.append(actual)
    if len(rows) != len(case.files) or len(review["files"]) != len(rows):
        raise AssertionError("incomplete invented proof")
    if (proposal["format"] != "outlands-source-export-proposal-v1"
            or review["format"] != "outlands-source-export-review-v1"
            or review["proposal_sha256"] != digest(proposal_raw)
            or review["publication_authorized"] is not False
            or not all(row[key] == "pending" for row in review["files"] for key in PENDING_FIELDS)):
        raise AssertionError("draft must remain entirely pending")
    marker = complete_value(case)
    claim = json.loads((case.output / "CLAIM.json").read_bytes())
    if (set(claim) != {"format", "status", "publication_authorized", "export_performed"}
            or claim["format"] != "outlands-source-export-intake-claim-v1" or claim["status"] != "HOLD"
            or claim["publication_authorized"] is not False or claim["export_performed"] is not False):
        raise AssertionError("intake claim must remain held without authority")
    if (set(marker) != {"format", "status", "publication_authorized", "export_performed", "files"}
            or marker["format"] != "outlands-source-export-intake-complete-v2"
            or marker["status"] != "HOLD" or marker["publication_authorized"] is not False
            or marker["export_performed"] is not False
            or marker["files"] != {name: digest((case.output / name).read_bytes()) for name in OUTPUT_ORDER[:-1]}):
        raise AssertionError("completion marker must bind all six draft buffers")
    binding = json.loads((case.output / "evidence-bindings.json").read_bytes())
    if (set(binding) != {"format", "selection_sha256", "policy", "files", "proposal_sha256", "review_draft_sha256"}
            or binding["format"] != "outlands-source-export-intake-bindings-v1"
            or binding["selection_sha256"] != digest(case.selection.read_bytes())
            or binding["policy"] != {"gate_sha256": digest(GATE.read_bytes()), "intake_sha256": digest(SCRIPT.read_bytes())}
            or binding["files"] != proposal["files"]
            or binding["proposal_sha256"] != digest(proposal_raw)
            or binding["review_draft_sha256"] != digest(review_raw)):
        raise AssertionError("persisted bindings must match exact inputs and policies")
    if (builder_result["status"] != "HOLD" or gate_result["eligibility"] != "HOLD"
            or gate_result["reason_codes"] != ["REVIEW_INCOMPLETE"] or gate_result["content_reads"] != 0):
        raise AssertionError("pending review must remain blocked before candidate reads")
    value = {"format": "outlands-private-intake-proof-v1", "label": label,
        "actual_file_count": len(rows), "actual_total_bytes": sum(row["bytes"] for row in rows),
        "builder_status": "HOLD", "gate_eligibility": "HOLD", "gate_reason_codes": ["REVIEW_INCOMPLETE"],
        "gate_content_reads": 0, "all_review_fields_pending": True, "complete_marker_verified": True,
        "publication_authorized": False, "export_performed": False,
        "source_map_sha256": digest(canonical(sorted(rows, key=lambda row: row["path"]))),
        "proposal_sha256": digest(proposal_raw), "review_sha256": digest(review_raw),
        "selection_sha256": digest(case.selection.read_bytes())}
    if set(value) != PROOF_FIELDS:
        raise AssertionError("private proof shape changed")
    runtime_value = os.environ.get("OUTLANDS_QUALIFICATION_RUNTIME")
    if runtime_value is not None:
        runtime = Path(runtime_value)
        if not runtime.is_absolute() or ".." in runtime.parts:
            raise AssertionError("private proof runtime must be absolute")
        root_fd = os.open(runtime, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(root_fd)
            if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
                raise AssertionError("unsafe private proof runtime")
            directory_fd = os.open("intake-measurements", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
            try:
                info = os.fstat(directory_fd)
                if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
                    raise AssertionError("unsafe private proof directory")
                fd = os.open(label + ".json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
                with os.fdopen(fd, "wb") as output:
                    info = os.fstat(output.fileno())
                    if stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1:
                        raise AssertionError("unsafe new private proof")
                    output.write(canonical(value))
                    output.flush()
                    os.fsync(output.fileno())
            finally:
                os.close(directory_fd)
        finally:
            os.close(root_fd)
    return value


class BuildReviewIntakeCliTests(unittest.TestCase):
    def run_script(self, script, arguments, root):
        completed = subprocess.run([sys.executable, "-I", "-B", str(script), *arguments],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=False, cwd=root,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1"})
        self.assertEqual(completed.stderr, b"")
        self.assertLessEqual(len(completed.stdout), 262144)
        self.assertEqual(len(completed.stdout.splitlines()), 1)
        self.assertNotIn(str(root).encode(), completed.stdout)
        self.assertNotIn(b"INVENTED_DO_NOT_ECHO", completed.stdout)
        self.assertIsNone(re.search(rb"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", completed.stdout))
        return completed, json.loads(completed.stdout)

    def invoke(self, case, status="HOLD", *, output=None, arguments=None):
        before = snapshot(case.root)
        target = case.output if output is None else output
        args = ["--candidate", str(case.candidate), "--selection", str(case.selection), "--output", str(target)]
        completed, value = self.run_script(SCRIPT, args if arguments is None else arguments, case.root)
        self.assertEqual(completed.returncode, 1 if status == "HOLD" else 2)
        self.assertEqual(set(value), SUMMARY_FIELDS)
        self.assertEqual(value["format"], "outlands-private-review-intake-cli-v1")
        self.assertEqual(value["status"], status)
        self.assertEqual(value["publication_status"], "HELD")
        for key in ("publication_authorized", "export_performed", "destination_verified", "git_metadata_reviewed", "scanner_called"):
            self.assertIs(value[key], False)
        after = snapshot(case.root)
        if status == "HOLD":
            self.assertEqual(value["reason_codes"], ["REVIEW_PENDING"])
            self.assertEqual(value["files_written"], list(OUTPUT_ORDER))
            self.assertIs(value["complete_written"], True)
            self.assertIs(value["draft_created"], True)
            self.assertEqual(value["content_reads"], len(case.files))
            self.assertEqual(value["recheck_reads"], 2 * len(case.files))
            self.assertEqual(set(after) - set(before), {"intake", *("intake/" + name for name in OUTPUT_ORDER)})
            for name, row in before.items():
                self.assertEqual(after[name][:4] if name == "." else after[name], row[:4] if name == "." else row)
            for path in case.output.iterdir():
                info = path.lstat()
                self.assertEqual((stat.S_IMODE(info.st_mode), info.st_uid, info.st_nlink), (0o600, os.getuid(), 1))
            self.assertEqual(stat.S_IMODE(case.output.stat().st_mode), 0o700)
            self.assertEqual((case.output / "CHECKLIST.md").read_bytes(), (case.output / "CHECKLIST.txt").read_bytes())
        else:
            self.assertEqual(after, before)
            self.assertIs(value["complete_written"], False)
        return value

    def test_mixed_unicode_intake_stays_pending_and_gate_holds_before_content(self):
        with intake_fixture() as case:
            built = self.invoke(case)
            before = {str(path): snapshot(path) for path in (case.candidate, case.selection, case.output)}
            process, gate_result = self.run_script(GATE, ["--candidate", str(case.candidate), "--proposal", str(case.proposal),
                "--review", str(case.review), "--receipt", str(case.gate_receipt), "--eligibility-only"], case.root)
            self.assertEqual(process.returncode, 1)
            self.assertEqual((gate_result["eligibility"], gate_result["reason_codes"], gate_result["content_reads"]),
                             ("HOLD", ["REVIEW_INCOMPLETE"], 0))
            self.assertEqual({str(path): snapshot(path) for path in (case.candidate, case.selection, case.output)}, before)
            proof = pending_proof(case, "cli-pending", built, gate_result)
            self.assertEqual(proof["actual_file_count"], 3)

    def test_all_eight_family_labels_are_explicit_not_inferred(self):
        for family in FAMILIES:
            with self.subTest(family=family), intake_fixture(family=family) as case:
                self.invoke(case)
                self.assertEqual(json.loads(case.proposal.read_bytes())["family"], family)

    def test_unselected_secrets_fifo_and_link_are_neither_read_nor_listed(self):
        with intake_fixture() as case:
            write_private(case.candidate / "unselected.env", b"INVENTED_DO_NOT_ECHO=fake-only\n")
            os.mkfifo(case.candidate / "unselected.pipe", mode=0o600)
            (case.candidate / "unselected-link").symlink_to(case.root / "absent")
            self.invoke(case)
            public = b"".join(path.read_bytes() for path in case.output.iterdir())
            for name in (b"unselected.env", b"unselected.pipe", b"unselected-link"):
                self.assertNotIn(name, public)
            self.assertNotIn(b"INVENTED_DO_NOT_ECHO", public)
            self.assertNotIn(b"INVENTED_DO_NOT_ECHO=fake-only\n", public)
            selected = {row["path"] for row in case.selection_doc["files"]}
            self.assertEqual({row["path"] for row in json.loads(case.proposal.read_bytes())["files"]}, selected)
            self.assertEqual({row["path"] for row in json.loads(case.review.read_bytes())["files"]}, selected)

    def test_notice_documentation_and_true_synthetic_example_remain_pending(self):
        for name, kind, synthetic in (("NOTICE.txt", "notice", False), ("guide.md", "documentation", False),
                                      ("examples/invented.json", "synthetic_example", True)):
            with self.subTest(kind=kind), intake_fixture(files={name: b"Invented portable text.\n"}, kinds={name: kind}, synthetic=synthetic) as case:
                self.invoke(case)
                review = json.loads(case.review.read_bytes())
                self.assertTrue(all(row[key] == "pending" for row in review["files"] for key in PENDING_FIELDS))

    def test_malformed_selection_is_refused_without_candidate_reads(self):
        for change in ("json", "duplicate-json", "nonfinite", "unknown", "family", "bool", "unsorted", "duplicate", "count"):
            with self.subTest(change=change), intake_fixture() as case:
                if change == "json": raw = b'{"INVENTED_DO_NOT_ECHO":'
                elif change == "duplicate-json": raw = b'{"format":"x","format":"y"}'
                elif change == "nonfinite": raw = b'{"files":NaN}'
                else:
                    if change == "unknown": case.selection_doc["private"] = "INVENTED_DO_NOT_ECHO"
                    elif change == "family": case.selection_doc["family"] = "fictional-unknown"
                    elif change == "bool": case.selection_doc["files"][0]["synthetic_fixture"] = 0
                    elif change == "unsorted": case.selection_doc["files"].reverse()
                    elif change == "duplicate": case.selection_doc["files"].append(dict(case.selection_doc["files"][-1]))
                    else: case.selection_doc["files"] = [{"path": "f%03d.py" % i, "artifact_kind": "source", "synthetic_fixture": False} for i in range(129)]
                    raw = canonical(case.selection_doc)
                write_private(case.selection, raw, replace=True)
                self.assertEqual(self.invoke(case, "REFUSED")["content_reads"], 0)

    def test_utf8_nul_and_actual_file_and_batch_byte_bounds(self):
        scenarios = [("utf8", {"x.py": b"\xff"}, False), ("nul", {"x.py": b"#\x00"}, False),
                     ("file-exact", sized_files(1, 2000000), True), ("file-over", sized_files(1, 2000001), False),
                     ("batch-exact", sized_files(5, 1600000), True), ("batch-over", sized_files(5, 1600000), False)]
        for label, files, valid in scenarios:
            if label == "batch-over": files[sorted(files)[-1]] += b"\n"
            with self.subTest(label=label), intake_fixture(files=files) as case:
                value = self.invoke(case, "HOLD" if valid else "REFUSED")
                if label.endswith("over"):
                    self.assertEqual(value["content_reads"], 0)

    def test_links_and_unsafe_selected_members_are_refused(self):
        for change in ("member-link", "member-hardlink", "parent-link", "root-link", "selection-link", "selection-hardlink", "directory"):
            with self.subTest(change=change), intake_fixture() as case:
                member = case.candidate / case.selection_doc["files"][0]["path"]
                if change.startswith("selection"):
                    outside = case.root / "invented-selection.json"
                    write_private(outside, case.selection.read_bytes())
                    case.selection.unlink()
                    if change == "selection-link": case.selection.symlink_to(outside)
                    else: os.link(outside, case.selection)
                elif change == "root-link":
                    original = case.root / "original-candidate"
                    case.candidate.rename(original)
                    case.candidate.symlink_to(original, target_is_directory=True)
                elif change == "parent-link":
                    original = case.root / "original-docs"
                    member.parent.rename(original)
                    member.parent.symlink_to(original, target_is_directory=True)
                else:
                    outside = case.root / "invented-member.txt"
                    write_private(outside, member.read_bytes())
                    member.unlink()
                    if change == "member-link": member.symlink_to(outside)
                    elif change == "member-hardlink": os.link(outside, member)
                    else: member.mkdir(mode=0o700)
                self.invoke(case, "REFUSED")

    def test_unsafe_or_overlapping_destinations_are_refused_without_adoption(self):
        for change in ("existing-dir", "existing-file", "dangling", "candidate", "ancestor", "selection", "parent-mode"):
            with self.subTest(change=change), intake_fixture() as case:
                target = case.output
                if change == "existing-dir": target.mkdir(mode=0o700)
                elif change == "existing-file": write_private(target, b"invented existing\n")
                elif change == "dangling": target.symlink_to(case.root / "absent")
                elif change == "candidate": target = case.candidate / "output"
                elif change == "ancestor": target = case.root
                elif change == "selection": target = case.selection
                else:
                    parent = case.root / "public-parent"
                    parent.mkdir(mode=0o700)
                    parent.chmod(0o755)
                    target = parent / "output"
                self.assertEqual(self.invoke(case, "REFUSED", output=target)["content_reads"], 0)

    def test_completed_output_is_never_overwritten_on_a_second_request(self):
        with intake_fixture() as case:
            self.invoke(case)
            self.assertEqual(self.invoke(case, "REFUSED")["content_reads"], 0)

    def test_missing_paths_and_strict_arguments_have_finite_redacted_refusals(self):
        for change in ("missing", "arguments", "abbreviation"):
            with self.subTest(change=change), intake_fixture() as case:
                args = None
                if change == "missing": case.selection.unlink()
                elif change == "arguments": args = ["--candidate", "/invented/private/INVENTED_DO_NOT_ECHO"]
                else: args = ["--cand", str(case.candidate), "--selection", str(case.selection), "--output", str(case.output)]
                self.assertEqual(self.invoke(case, "REFUSED", arguments=args)["content_reads"], 0)


if __name__ == "__main__":
    unittest.main()
