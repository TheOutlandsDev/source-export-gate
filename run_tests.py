"""One combined synthetic suite; caller supplies an optional external namespace fence.

Inherited TemporaryDirectory teardown is unchanged, including after assertions.
Logs, outcomes and six measurements are retained; this runner does not retain
every transient fixture tree. No old evidence or interruption worker is opened.
"""
import argparse
import tempfile
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import unittest

SUITES = (
    ("gate-unit", "test_source_export_gate.py", "unit"),
    ("gate-cli", "test_source_export_gate_cli.py", "cli"),
    ("receipt-unit", "test_source_export_receipt.py", "unit"),
    ("receipt-cli", "test_source_export_receipt_cli.py", "cli"),
    ("coverage-unit", "test_batch_coverage.py", "unit"),
    ("coverage-cli", "test_batch_coverage_cli.py", "cli"),
    ("large-unit", "test_large_candidate.py", "unit"),
    ("large-cli", "test_large_candidate_cli.py", "cli"),
    ("coverage-receipt-unit", "test_coverage_receipts.py", "unit"),
    ("coverage-receipt-cli", "test_coverage_receipts_cli.py", "cli"),
    ("intake-unit", "test_build_review_intake.py", "unit"),
    ("intake-cli", "test_build_review_intake_cli.py", "cli"),
    ("intake-verify", "test_verify_review_intake.py", "cli"),
)
EXPECTED_METHODS = (37, 29, 26, 13, 29, 12, 5, 5, 19, 10, 30, 10, 43)
EXPECTED_TOTAL = 268
EXPECTED_OWNED_CLI = 425
assert __debug__
parser = argparse.ArgumentParser(description="One synthetic offline suite; output must be new and private.")
parser.add_argument("--output", required=True)
args = parser.parse_args()
source, runtime = Path(__file__).absolute().parent, Path(args.output)
assert source.resolve() == source and runtime.is_absolute() and ".." not in runtime.parts
assert source != runtime and source not in runtime.parents and runtime not in source.parents
assert runtime.parent.resolve() == runtime.parent and runtime.parent.stat().st_uid == os.getuid()
assert stat.S_IMODE(runtime.parent.stat().st_mode) == 0o700
os.umask(0o077)
runtime.mkdir(mode=0o700)
for name in ("tmp", "measurements", "intake-measurements"):
    (runtime / name).mkdir(mode=0o700)
os.environ["TMPDIR"] = str(runtime / "tmp")
os.environ["OUTLANDS_QUALIFICATION_RUNTIME"] = str(runtime)
tempfile.tempdir = str(runtime / "tmp")
namespace_separate = all(os.environ.get("OUTLANDS_TEST_HOST_" + name.upper()) not in (None, os.readlink("/proc/self/ns/" + name)) for name in ("net", "pid"))
sys.dont_write_bytecode = True
sys.path.insert(0, str(source))
engines = {str(source / name) for name in ("source_export_gate.py", "verify_source_export_receipt.py", "verify_batch_coverage.py", "coverage_receipts.py", "build_review_intake.py", "verify_review_intake.py")}
state = {"phase": "unit", "denied": [], "owned_cli_launches": 0}

def audit(event, arguments):
    if event == "subprocess.Popen":
        executable, command, cwd, env = arguments
        safe = (
            state["phase"] == "cli" and executable == sys.executable
            and type(command) in (list, tuple) and 4 <= len(command) <= 32
            and list(command[:3]) == [sys.executable, "-I", "-B"]
            and type(command[3]) is str and command[3] in engines
            and all(type(value) is str and len(value) <= 4096 and "\x00" not in value for value in command)
            and type(cwd) in (str, type(runtime)) and Path(cwd).is_absolute()
            and ".." not in Path(cwd).parts and Path(cwd).is_relative_to(runtime / "tmp")
            and env == {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1"}
        )
        if safe:
            state["owned_cli_launches"] += 1
            return
        state["denied"].append(event)
        raise RuntimeError("UNAPPROVED_PROCESS")
    if (event.startswith("socket.") or event.startswith("subprocess.")
            or event.startswith("http.client.") or event.startswith("os.exec")
            or event.startswith("os.spawn") or event.startswith("os.posix_spawn")
            or event in {"os.system", "os.fork", "os.forkpty", "os.kill", "os.killpg",
                         "pty.spawn", "urllib.Request"}):
        state["denied"].append(event)
        raise RuntimeError("EXTERNAL_OPERATION_DENIED")

sys.addaudithook(audit)

def write_private(name, raw):
    fd = os.open(runtime / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(fd)


MEASUREMENTS = {
    "unit-eligibility": "NOT_RUN", "unit-screen-clean": "PASS", "unit-screen-finding": "REVIEW",
    "cli-eligibility": "NOT_RUN", "cli-screen-clean": "PASS", "cli-screen-finding": "REVIEW",
}
MEASUREMENT_FIELDS = {
    "format", "label", "file_count", "actual_total_bytes", "files_per_batch", "bytes_per_batch",
    "min_file_bytes", "max_file_bytes", "all_files_utf8", "source_map_sha256", "result_status",
    "text_review", "content_reads", "scanner_called", "member_bytes_observed", "publication_authorized",
}

def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            assert key not in value
            value[key] = item
        return value
    def invalid(_value):
        raise ValueError("NONFINITE_JSON")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid)

def validate_measurements(hashes):
    directory = runtime / "measurements"
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(directory, flags)
    try:
        before = os.fstat(fd)
        assert stat.S_ISDIR(before.st_mode) and before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o700
        expected = {label + ".json" for label in MEASUREMENTS}
        names = set()
        with os.scandir(fd) as entries:
            for entry in entries:
                names.add(entry.name)
                assert len(names) <= len(expected)
        assert names == expected
        for label, text_state in MEASUREMENTS.items():
            name = label + ".json"
            initial = os.stat(name, dir_fd=fd, follow_symlinks=False)
            assert stat.S_ISREG(initial.st_mode) and initial.st_uid == os.getuid() and initial.st_nlink == 1
            assert stat.S_IMODE(initial.st_mode) == 0o600 and 0 < initial.st_size <= 16384
            member = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                assert identity(os.fstat(member)) == identity(initial)
                data = bytearray()
                while len(data) <= 16384:
                    chunk = os.read(member, min(4096, 16385 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                final = os.fstat(member)
                named = os.stat(name, dir_fd=fd, follow_symlinks=False)
                assert len(data) == initial.st_size <= 16384
                assert identity(initial) == identity(final) == identity(named)
                raw = bytes(data)
            finally:
                os.close(member)
            hashes[name] = hashlib.sha256(raw).hexdigest()
            value = strict_json(raw)
            assert type(value) is dict and set(value) == MEASUREMENT_FIELDS
            assert value["format"] == "outlands-large-candidate-measurement-v1" and value["label"] == label
            for field, expected_value in (("file_count", 129), ("actual_total_bytes", 9030000),
                ("min_file_bytes", 70000), ("max_file_bytes", 70000), ("content_reads", 129)):
                assert type(value[field]) is int and value[field] == expected_value
            for field, expected_value in (("files_per_batch", [64, 65]), ("bytes_per_batch", [4480000, 4550000])):
                assert type(value[field]) is list and len(value[field]) == 2
                assert all(type(item) is int for item in value[field]) and value[field] == expected_value
            assert value["all_files_utf8"] is True
            assert type(value["source_map_sha256"]) is str and re.fullmatch(r"[a-f0-9]{64}", value["source_map_sha256"])
            assert value["result_status"] == "MATCHED" and value["text_review"] == text_state
            assert value["scanner_called"] is False and value["publication_authorized"] is False
            if label.startswith("unit-"):
                assert type(value["member_bytes_observed"]) is int and value["member_bytes_observed"] == 9030000
            else:
                assert value["member_bytes_observed"] is None
        assert identity(os.fstat(fd)) == identity(before)
        assert identity(directory.lstat()) == identity(before)
    finally:
        os.close(fd)

write_private("SUITE-CLAIM.json", (json.dumps({
    "format": "outlands-private-regression-suite-claim-v1", "suite_run": 1,
    "retry_count": 0, "historical_interruption_workers_rerun": 0,
    "publication_authorized": False}, sort_keys=True, separators=(",", ":")) + "\n").encode())

INTAKE_FIELDS = {"format", "label", "actual_file_count", "actual_total_bytes", "builder_status", "gate_eligibility",
    "gate_reason_codes", "gate_content_reads", "all_review_fields_pending", "complete_marker_verified",
    "publication_authorized", "export_performed", "source_map_sha256", "proposal_sha256", "review_sha256", "selection_sha256"}


def validate_intake_proofs(hashes):
    directory = runtime / "intake-measurements"
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        assert stat.S_ISDIR(before.st_mode) and before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o700
        assert set(os.listdir(fd)) == {"unit-pending.json", "cli-pending.json"}
        values = []
        for label in ("unit-pending", "cli-pending"):
            name = label + ".json"
            initial = os.stat(name, dir_fd=fd, follow_symlinks=False)
            assert stat.S_ISREG(initial.st_mode) and initial.st_uid == os.getuid() and initial.st_nlink == 1
            assert stat.S_IMODE(initial.st_mode) == 0o600 and 0 < initial.st_size <= 16384
            member = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                assert identity(os.fstat(member)) == identity(initial)
                chunks, total = [], 0
                while total <= 16384:
                    chunk = os.read(member, min(4096, 16385 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                raw = b"".join(chunks)
                assert len(raw) == initial.st_size <= 16384
                assert identity(initial) == identity(os.fstat(member)) == identity(os.stat(name, dir_fd=fd, follow_symlinks=False))
            finally:
                os.close(member)
            value = strict_json(raw)
            assert type(value) is dict and set(value) == INTAKE_FIELDS and value["format"] == "outlands-private-intake-proof-v1" and value["label"] == label
            assert type(value["actual_file_count"]) is int and value["actual_file_count"] == 3
            assert type(value["actual_total_bytes"]) is int and value["actual_total_bytes"] == 136
            assert value["builder_status"] == value["gate_eligibility"] == "HOLD" and value["gate_reason_codes"] == ["REVIEW_INCOMPLETE"]
            assert type(value["gate_content_reads"]) is int and value["gate_content_reads"] == 0
            assert value["all_review_fields_pending"] is True and value["complete_marker_verified"] is True
            assert value["publication_authorized"] is False and value["export_performed"] is False
            for key in ("source_map_sha256", "proposal_sha256", "review_sha256", "selection_sha256"):
                assert type(value[key]) is str and re.fullmatch(r"[a-f0-9]{64}", value[key])
            hashes[name] = hashlib.sha256(raw).hexdigest()
            values.append({key: val for key, val in value.items() if key != "label"})
        assert values[0] == values[1]
        assert identity(os.fstat(fd)) == identity(before) == identity(directory.lstat())
    finally:
        os.close(fd)


summary = {
    "format": "outlands-combined-source-gate-tests-v1", "status": "FAILED", "suites": [],
    "suite_runs": 1, "historical_native_requalification": False,
    "interruption_workers_rerun": 0, "retry_count": 0,
    "publication_authorized": False, "real_source_families_read": False,
    "live_provider_or_inference": False, "namespace_separate": namespace_separate,
    "measurement_files": {}, "measurement_validation": {"status": "NOT_RUN", "reason_codes": []},
    "intake_proof_files": {}, "intake_proof_validation": {"status": "NOT_RUN", "reason_codes": []},
}
assert len(SUITES) == len(EXPECTED_METHODS) == 13 and sum(EXPECTED_METHODS) == EXPECTED_TOTAL
for (label, pattern, phase), expected_methods in zip(SUITES, EXPECTED_METHODS):
    state["phase"] = phase
    assert (source / pattern).is_file()
    suite = unittest.TestLoader().discover(str(source), pattern=pattern)
    assert suite.countTestCases() == expected_methods
    log = io.StringIO()
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    write_private(label + ".log", log.getvalue().encode())
    row = {
        "phase": label, "pattern": pattern, "methods": result.testsRun,
        "expected_methods": expected_methods,
        "failures": len(result.failures), "errors": len(result.errors), "skips": len(result.skipped),
        "expected_failures": len(result.expectedFailures), "unexpected_successes": len(result.unexpectedSuccesses),
        "passed": bool(result.testsRun == expected_methods and result.wasSuccessful()
                       and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses),
    }
    summary["suites"].append(row)
    if not row["passed"]:
        break
summary["denied_events"] = state["denied"]
summary["owned_cli_launches"] = state["owned_cli_launches"]
summary["methods"] = sum(row["methods"] for row in summary["suites"])
if (len(summary["suites"]) == len(SUITES) and all(row["passed"] for row in summary["suites"])
        and summary["methods"] == EXPECTED_TOTAL and summary["owned_cli_launches"] == EXPECTED_OWNED_CLI
        and not state["denied"]):
    try:
        validate_measurements(summary["measurement_files"])
    except Exception:
        summary["measurement_validation"] = {"status": "FAILED", "reason_codes": ["MEASUREMENT_INVALID"]}
    else:
        summary["measurement_validation"] = {"status": "PASS", "reason_codes": []}
        try:
            validate_intake_proofs(summary["intake_proof_files"])
        except Exception:
            summary["intake_proof_validation"] = {"status": "FAILED", "reason_codes": ["INTAKE_PROOF_INVALID"]}
        else:
            summary["intake_proof_validation"] = {"status": "PASS", "reason_codes": []}
            summary["status"] = "PASS"
write_private("TEST-RESULT.json", (json.dumps(summary, indent=2) + "\n").encode())
print(json.dumps(summary), flush=True)
raise SystemExit(0 if summary["status"] == "PASS" else 1)
