"""Actual bounded CLIs over fresh sized comments; never a live-source audit.

The plain helpers are shared with the guarded library suite. CLI children use
the three existing fixed scripts only, with no qualification-runtime variable.
Measurements describe observed fixture bytes, not child syscall attestation.
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

from test_batch_coverage_cli import (COVERAGE, MARKER, SUMMARY_FIELDS, WRITER,
    batch_fixture, canonical, child_result, digest, snapshot, write_private,
    writer_args)


MEASUREMENT_LABELS = frozenset({"unit-eligibility", "unit-screen-clean", "unit-screen-finding",
                               "cli-eligibility", "cli-screen-clean", "cli-screen-finding"})
MEASUREMENT_FIELDS = frozenset({"format", "label", "file_count", "actual_total_bytes",
    "files_per_batch", "bytes_per_batch", "min_file_bytes", "max_file_bytes", "all_files_utf8",
    "source_map_sha256", "result_status", "text_review", "content_reads", "scanner_called",
    "member_bytes_observed", "publication_authorized"})


def sized_files(count=129, size=70000, finding=False):
    """Return exact-size UTF-8 Python/Java comments with short physical lines."""
    if type(count) is not int or count < 1 or type(size) is not int or type(finding) is not bool:
        raise ValueError("invalid invented text dimensions")
    names = sorted("src/" + (("Invented%04d.java" if index % 2 else "invented%04d.py") % index)
                   for index in range(count))
    files = {}
    for name in names:
        prefix = b"// " if name.endswith(".java") else b"# "
        header = prefix + "Invented UTF-8 comments — café; never executed or compiled.\n".encode("utf-8")
        if finding and name == names[-1]:
            header += prefix + MARKER.encode("ascii") + b"\n"
        minimum_tail = len(prefix) + 1
        if size < len(header) + minimum_tail:
            raise ValueError("invented text size cannot hold its header")
        line = prefix + b"x" * 60 + b"\n"
        repeats = (size - len(header) - minimum_tail) // len(line)
        tail_size = size - len(header) - repeats * len(line)
        raw = header + line * repeats + prefix + b"x" * (tail_size - minimum_tail) + b"\n"
        if len(raw) != size or b"\x00" in raw or max(map(len, raw.splitlines())) > 128:
            raise AssertionError("invented text construction failed")
        raw.decode("utf-8")
        files[name] = raw
    return files


@contextmanager
def large_fixture(*, screened=False, finding=False, counts=(64, 65), size=70000, files=None):
    """Use the unchanged batch fixture with newly constructed actual bytes."""
    payload = sized_files(sum(counts), size, finding) if files is None else files
    with batch_fixture(files=payload, counts=counts, screened=screened) as case:
        yield case


def _private_directory(info):
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
        raise AssertionError("measurement destination must be an owned private directory")


def _record_measurement(label, measurement):
    runtime_value = os.environ.get("OUTLANDS_QUALIFICATION_RUNTIME")
    if runtime_value is None:
        return
    runtime = Path(runtime_value)
    if not runtime.is_absolute() or ".." in runtime.parts:
        raise AssertionError("qualification runtime must be absolute")
    root_fd = os.open(runtime, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _private_directory(os.fstat(root_fd))
        directory_fd = os.open("measurements", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            _private_directory(os.fstat(directory_fd))
            output_fd = os.open(label + ".json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                0o600, dir_fd=directory_fd)
            with os.fdopen(output_fd, "wb") as output:
                info = os.fstat(output.fileno())
                if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                        or info.st_uid != os.getuid() or info.st_nlink != 1):
                    raise AssertionError("unsafe new measurement file")
                output.write(canonical(measurement))
                output.flush()
                os.fsync(output.fileno())
        finally:
            os.close(directory_fd)
    finally:
        os.close(root_fd)


def measure_and_record(case, label, report, member_bytes=None):
    """Independently hash actual fixture bytes; record only within the harness."""
    if label not in MEASUREMENT_LABELS or not (member_bytes is None or type(member_bytes) is int and member_bytes >= 0):
        raise AssertionError("invalid measurement metadata")
    expected = {row["path"]: row for row in case.manifest_doc["files"]}
    if len(expected) != len(case.manifest_doc["files"]):
        raise AssertionError("duplicate measured manifest path")
    measured, per_batch, bytes_per_batch = {}, [], []
    for batch in case.batches:
        count, total = 0, 0
        for row in batch.fx.proposal_doc["files"]:
            name = row["path"]
            path = batch.fx.candidate / name
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os.getuid() or info.st_nlink != 1 or name in measured):
                raise AssertionError("unsafe or duplicated measured fixture member")
            parent = path.parent
            while True:
                _private_directory(parent.lstat())
                if parent == batch.fx.candidate:
                    break
                parent = parent.parent
            raw = path.read_bytes()
            if b"\x00" in raw:
                raise AssertionError("measured member contains NUL")
            raw.decode("utf-8")
            current = {"path": name, "sha256": digest(raw), "bytes": len(raw)}
            declared = expected.get(name)
            if declared is None or any(current[key] != declared[key] for key in current) or len(raw) != info.st_size:
                raise AssertionError("measured bytes disagree with the full manifest")
            if any(row[key] != declared[key] for key in declared):
                raise AssertionError("batch row differs from the full manifest")
            measured[name] = current
            count += 1
            total += len(raw)
        per_batch.append(count)
        bytes_per_batch.append(total)
    if set(measured) != set(expected) or not measured:
        raise AssertionError("measurement does not cover the full declared manifest")
    for key in ("scanner_called", "publication_authorized", "export_performed", "destination_verified", "git_metadata_reviewed"):
        if report[key] is not False:
            raise AssertionError("measurement cannot confer authority or rerun a screen")
    ordered = [measured[name] for name in sorted(measured)]
    value = {"format": "outlands-large-candidate-measurement-v1", "label": label,
        "file_count": len(ordered), "actual_total_bytes": sum(row["bytes"] for row in ordered),
        "files_per_batch": per_batch, "bytes_per_batch": bytes_per_batch,
        "min_file_bytes": min(row["bytes"] for row in ordered), "max_file_bytes": max(row["bytes"] for row in ordered),
        "all_files_utf8": True, "source_map_sha256": digest(canonical(ordered)),
        "result_status": report["status"], "text_review": report["text_review"],
        "content_reads": report["content_reads"], "scanner_called": False,
        "member_bytes_observed": member_bytes, "publication_authorized": False}
    if set(value) != MEASUREMENT_FIELDS:
        raise AssertionError("measurement shape drift")
    _record_measurement(label, value)
    return value


class LargeCandidateCliTests(unittest.TestCase):
    def run_script(self, script, args, root):
        completed = subprocess.run([sys.executable, "-I", "-B", str(script), *args],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=False, cwd=root,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1"})
        self.assertEqual(completed.stderr, b"")
        self.assertLessEqual(len(completed.stdout), 262144)
        self.assertEqual(len(completed.stdout.splitlines()), 1)
        self.assertIsNone(re.search(rb"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", completed.stdout))
        self.assertNotIn(str(root).encode(), completed.stdout)
        self.assertNotIn(MARKER.encode(), completed.stdout)
        return completed, json.loads(completed.stdout)

    def writer(self, batch, *, refused=False):
        before = {str(path): snapshot(path) for path in (batch.fx.candidate, batch.fx.proposal, batch.fx.review)}
        process, value = self.run_script(WRITER, writer_args(batch), batch.fx.root)
        self.assertEqual(process.returncode, 2 if refused else 1 if value["text_review"] == "REVIEW" else 0)
        self.assertEqual(value["eligibility"], "REFUSED" if refused else "ELIGIBLE_FOR_TEXT_REVIEW")
        self.assertEqual({str(path): snapshot(path) for path in (batch.fx.candidate, batch.fx.proposal, batch.fx.review)}, before)
        self.assertTrue((batch.fx.receipt / "COMPLETE.json").is_file())
        if refused:
            self.assertEqual(value["content_reads"], 0)
            self.assertIs(value["scanner_called"], False)
            self.assertIsNone(child_result(batch)["bindings"])
        return value

    def coverage(self, case, *, status="MATCHED", text="NOT_RUN", reads=129):
        before = snapshot(case.root)
        process, value = self.run_script(COVERAGE, ["--manifest", str(case.manifest), "--plan", str(case.plan)], case.root)
        self.assertEqual(snapshot(case.root), before)
        self.assertEqual(set(value), SUMMARY_FIELDS)
        self.assertEqual(process.returncode, 0 if status == "MATCHED" and text != "REVIEW" else 1)
        self.assertEqual((value["status"], value["text_review"], value["content_reads"]), (status, text, reads))
        self.assertEqual(value["publication_status"], "HELD")
        for key in ("scanner_called", "publication_authorized", "export_performed", "destination_verified", "git_metadata_reviewed"):
            self.assertIs(value[key], False)
        return value

    def assert_profile(self, case, label, report):
        before = snapshot(case.root)
        measured = measure_and_record(case, label, report)
        self.assertEqual(snapshot(case.root), before)
        self.assertEqual((measured["file_count"], measured["actual_total_bytes"]), (129, 9030000))
        self.assertEqual(measured["files_per_batch"], [64, 65])
        self.assertEqual(measured["bytes_per_batch"], [4480000, 4550000])
        self.assertEqual((measured["min_file_bytes"], measured["max_file_bytes"]), (70000, 70000))
        self.assertIsNone(measured["member_bytes_observed"])

    def test_actual_9030000_byte_eligibility_profile(self):
        with large_fixture() as case:
            case.make_receipts(self.writer)
            report = self.coverage(case)
            self.assertEqual((report["declared_files"], report["covered_files"], report["verified_batches"]), (129, 129, 2))
            self.assert_profile(case, "cli-eligibility", report)

    def test_actual_9030000_byte_screen_clean_and_findings_profiles(self):
        for finding in (False, True):
            with self.subTest(finding=finding), large_fixture(screened=True, finding=finding) as case:
                case.make_receipts(self.writer)
                report = self.coverage(case, text="REVIEW" if finding else "PASS")
                self.assertEqual(report["finding_count"] > 0, finding)
                self.assert_profile(case, "cli-screen-finding" if finding else "cli-screen-clean", report)

    def test_actual_single_file_two_million_bytes_and_plus_one_refusal(self):
        for size in (2000000, 2000001):
            with self.subTest(size=size), large_fixture(counts=(1,), size=size) as case:
                self.assertEqual(sum(len(raw) for raw in case.files.values()), size)
                batch = case.batches[0]
                self.writer(batch, refused=size > 2000000)
                if size == 2000000:
                    value = self.coverage(case, reads=1)
                    self.assertEqual(value["covered_files"], 1)

    def test_actual_batch_eight_million_bytes_and_plus_one_refusal(self):
        for extra in (False, True):
            files = sized_files(count=5, size=1600000)
            if extra:
                name = sorted(files)[-1]
                files[name] += b"\n"
            with self.subTest(extra=extra), large_fixture(counts=(5,), files=files) as case:
                self.assertEqual(sum(len(raw) for raw in case.files.values()), 8000001 if extra else 8000000)
                self.assertTrue(all(len(raw) <= 2000000 for raw in case.files.values()))
                self.writer(case.batches[0], refused=extra)
                if not extra:
                    self.assertEqual(self.coverage(case, reads=5)["covered_files"], 5)

    def test_same_size_second_batch_mutation_preserves_65_attempted_reads(self):
        with large_fixture() as case:
            case.make_receipts(self.writer)
            batch = case.batches[1]
            member = batch.fx.candidate / batch.fx.proposal_doc["files"][0]["path"]
            raw = member.read_bytes()
            changed = raw.replace(b"Invented", b"Modified", 1)
            self.assertEqual(len(changed), len(raw))
            self.assertNotEqual(changed, raw)
            write_private(member, changed, replace=True)
            report = self.coverage(case, status="STALE", reads=65)
            self.assertEqual(report["verified_batches"], 1)
            self.assertEqual(report["finding_count"], 0)


if __name__ == "__main__":
    unittest.main()
