"""Read-only consistency of a declared private manifest and disjoint receipts.

Coverage is unsigned evidence, not source discovery, screening or release consent.
"""

import argparse
import errno
import importlib.util
import json
import os
from pathlib import Path
import re
import stat


_spec = importlib.util.spec_from_file_location(
    "outlands_coverage_verifier", Path(__file__).absolute().with_name("verify_source_export_receipt.py"))
verifier = importlib.util.module_from_spec(_spec)
exec(compile(_spec.loader.get_source(_spec.name), _spec.origin, "exec"), verifier.__dict__)
gate = verifier.gate

MAX_MANIFEST = 1048576
MAX_FILES = 1024
MAX_TOTAL = 32000000
MAX_BATCHES = 8
BATCH_ID = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
CHILD_FIELDS = {"format", "status", "reason_codes", "content_reads", "scanner_called",
                "publication_status", "publication_authorized", "export_performed",
                "destination_verified", "git_metadata_reviewed"}


class CoverageIssue(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status, self.code = status, code


def _need(condition, code, status="REFUSED"):
    if not condition:
        raise CoverageIssue(status, code)


def _result():
    return {"format": "outlands-batch-coverage-result-v1", "status": "REFUSED",
            "reason_codes": [], "family": None, "declared_files": 0, "covered_files": 0,
            "batch_count": 0, "verified_batches": 0, "content_reads": 0,
            "text_review": "NOT_RUN", "scanner_called": False, "findings": [],
            "batches": [], "bindings": None, "publication_status": "HELD",
            "publication_authorized": False, "export_performed": False,
            "destination_verified": False, "git_metadata_reviewed": False}


def _manifest(value):
    _need(gate._exact(value, {"format", "family", "review_mode", "publication_authorized", "files"})
          and value["format"] == "outlands-batch-coverage-manifest-v1"
          and type(value["family"]) is str and value["family"] in gate.FAMILIES
          and type(value["review_mode"]) is str
          and value["review_mode"] in {"eligibility_only", "screened"}
          and value["publication_authorized"] is False
          and type(value["files"]) is list and 1 <= len(value["files"]) <= MAX_FILES,
          "MANIFEST_SCHEMA")
    names, total = [], 0
    for row in value["files"]:
        # Validate each row without imposing an arbitrary contiguous 8MB partition.
        gate._proposal({"format": "outlands-source-export-proposal-v1",
                        "family": value["family"], "files": [row]})
        names.append(row["path"])
        total += row["bytes"]
    _need(names == sorted(set(names)) and total <= MAX_TOTAL, "MANIFEST_SCHEMA")


def _manifest_eligible(value):
    for row in value["files"]:
        _need(row["artifact_kind"] in gate.ELIGIBLE_KINDS and gate._path_eligible(row["path"])
              and (row["artifact_kind"] != "synthetic_example" or row["synthetic_fixture"] is True),
              "ARTIFACT_INELIGIBLE", "HOLD")


def _plan(value, mode):
    _need(gate._exact(value, {"format", "manifest_sha256", "batches"})
          and value["format"] == "outlands-batch-coverage-plan-v1"
          and verifier._digest(value["manifest_sha256"])
          and type(value["batches"]) is list and 1 <= len(value["batches"]) <= MAX_BATCHES,
          "PLAN_SCHEMA")
    names, rows = [], []
    for item in value["batches"]:
        _need(gate._exact(item, {"id", "candidate", "proposal", "review", "receipt", "scanner", "private_terms"})
              and type(item["id"]) is str and BATCH_ID.fullmatch(item["id"]), "PLAN_SCHEMA")
        row = {"id": item["id"]}
        for key in ("candidate", "proposal", "review", "receipt"):
            _need(type(item[key]) is str, "PLAN_SCHEMA")
            row[key] = gate._absolute(item[key])
        _need((item["scanner"] is None) == (item["private_terms"] is None), "PLAN_SCHEMA")
        _need((mode == "eligibility_only") == (item["scanner"] is None), "PLAN_SCHEMA")
        for key in ("scanner", "private_terms"):
            _need(item[key] is None or type(item[key]) is str, "PLAN_SCHEMA")
            row[key] = None if item[key] is None else gate._absolute(item[key])
        names.append(row["id"])
        rows.append(row)
    _need(names == sorted(set(names)), "PLAN_SCHEMA")
    return rows


def _fixed_paths():
    return {"gate": gate._absolute(gate.__file__), "verifier": gate._absolute(verifier.__file__),
            "coverage": gate._absolute(__file__)}


def _locations(manifest_path, plan_path, rows):
    roots = [row[key] for row in rows for key in ("candidate", "receipt")]
    _need(not any(gate._inside(a, b) or gate._inside(b, a)
                  for i, a in enumerate(roots) for b in roots[i + 1:]), "CONTROL_LOCATION")
    primary = [manifest_path, plan_path] + [row[key] for row in rows for key in ("proposal", "review")]
    scanners = {row["scanner"] for row in rows if row["scanner"] is not None}
    terms = {row["private_terms"] for row in rows if row["private_terms"] is not None}
    code = set(_fixed_paths().values())
    _need(len(set(primary)) == len(primary) and len(code) == 3
          and not set(primary) & (scanners | terms | code) and not scanners & terms
          and not (scanners | terms) & code, "CONTROL_LOCATION")
    controls = set(primary) | scanners | terms | code
    _need(not any(gate._inside(path, root) for path in controls for root in roots), "CONTROL_LOCATION")


def _control_metadata(path, maximum, trusted=False):
    """Check a control's metadata before consuming its bytes or accepting an alias."""
    fd = gate._open_dir(path.parent)
    try:
        if not trusted:
            gate._private_dir(fd)
        info = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
              and stat.S_IMODE(info.st_mode) in ({0o600, 0o644} if trusted else {0o600})
              and 0 <= info.st_size <= maximum, "INPUT_INVALID")
        return gate._identity(info)
    finally:
        os.close(fd)


def _read_control_snapshot(path, maximum, expected_pin=None):
    raw, pin = gate._read_control(path, maximum, expected_pin=expected_pin)
    return raw, (pin, gate._sha(raw))


def _code_snapshot():
    result = {}
    for key, path in _fixed_paths().items():
        raw, pin = gate._read_control(path, gate.MAX_META, trusted_code=True)
        result[key] = (pin, gate._sha(raw))
    return result


def _recheck_inputs(manifest_path, plan_path, input_pins):
    for path, maximum, expected in ((manifest_path, MAX_MANIFEST, input_pins[0]),
                                    (plan_path, gate.MAX_META, input_pins[1])):
        _raw, observed = _read_control_snapshot(path, maximum, expected[0])
        _need(observed == expected, "INPUT_CHANGED", "STALE")


def _controls(rows, manifest_path, plan_path, code_pins, input_pins):
    specifications = {manifest_path: (MAX_MANIFEST, False), plan_path: (gate.MAX_META, False)}
    for row in rows:
        for key in ("proposal", "review"):
            specifications[row[key]] = (gate.MAX_META, False)
        if row["scanner"] is not None:
            specifications[row["scanner"]] = (65536, False)
            specifications[row["private_terms"]] = (65536, False)
    pins, identities = {}, {value[0][:2] for value in code_pins.values()}
    _need(len(identities) == 3, "INPUT_INVALID")
    for path, (maximum, trusted) in specifications.items():
        pin = _control_metadata(path, maximum, trusted)
        _need(pin[:2] not in identities, "INPUT_INVALID")
        identities.add(pin[:2])
        pins[path] = (pin, maximum, trusted)
    _need(pins[manifest_path][0] == input_pins[0][0] and pins[plan_path][0] == input_pins[1][0],
          "INPUT_CHANGED", "STALE")
    return pins, identities


def _capture_controls(rows, control_pins, snapshots, identities):
    captured = {}
    for path, (expected, maximum, trusted) in control_pins.items():
        raw, pin = gate._read_control(path, maximum, trusted_code=trusted, expected_pin=expected,
                                      forbidden_ids=identities - {expected[:2]})
        captured[path] = (pin, gate._sha(raw))
    for item in rows:
        binding = snapshots[item["id"]]["result"]["bindings"]
        _need(captured[item["proposal"]][1] == binding["proposal_sha256"]
              and captured[item["review"]][1] == binding["review_sha256"], "INPUT_CHANGED", "STALE")
        if binding["screen"] is not None:
            _need(captured[item["scanner"]][1] == gate.SCANNER_SHA256 == binding["screen"]["scanner_sha256"]
                  and captured[item["private_terms"]][1] == binding["screen"]["private_terms_sha256"],
                  "INPUT_CHANGED", "STALE")
    return captured


def _record_snapshot(report, row, snapshot):
    result = snapshot["result"]
    row["eligibility"], row["text_review"] = result["eligibility"], result["text_review"]
    row["finding_count"] = len(result["findings"])
    report["findings"].extend({"batch_id": row["id"], "path": finding["path"], "check": finding["check"]}
                              for finding in result["findings"])


def _child_response(report, row, response, count):
    _need(type(response) is dict and verifier._integer(response.get("content_reads"), gate.MAX_FILES),
          "CHILD_RESPONSE_INVALID")
    report["content_reads"] += response["content_reads"]
    _need(gate._exact(response, CHILD_FIELDS)
          and response["format"] == "outlands-source-export-verification-v1"
          and type(response["status"]) is str
          and response["status"] in {"MATCHED", "STALE", "UNVERIFIABLE", "REFUSED"}
          and type(response["reason_codes"]) is list and len(response["reason_codes"]) <= 1
          and all(type(code) is str and gate.CODE.fullmatch(code) for code in response["reason_codes"])
          and response["scanner_called"] is False and response["publication_status"] == "HELD"
          and all(response[key] is False for key in verifier.AUTHORITY_FIELDS)
          and response["content_reads"] <= count, "CHILD_RESPONSE_INVALID")
    matched = response["status"] == "MATCHED"
    _need((matched and not response["reason_codes"] and response["content_reads"] == count)
          or (not matched and len(response["reason_codes"]) == 1), "CHILD_RESPONSE_INVALID")
    row["status"], row["reason_codes"] = response["status"], list(response["reason_codes"])
    if not matched:
        raise CoverageIssue(response["status"], "CHILD_" + response["status"])
    report["verified_batches"] += 1


def verify_coverage(manifest_path, plan_path):
    """Verify only this declared frozen union; leave every input untouched."""
    report, phase, active = _result(), "inputs", None
    try:
        manifest_path, plan_path = gate._absolute(manifest_path), gate._absolute(plan_path)
        _need(manifest_path != plan_path, "CONTROL_LOCATION")
        first_manifest = _control_metadata(manifest_path, MAX_MANIFEST)
        first_plan = _control_metadata(plan_path, gate.MAX_META)
        _need(first_manifest[:2] != first_plan[:2], "INPUT_INVALID")
        manifest_raw, manifest_pin = _read_control_snapshot(manifest_path, MAX_MANIFEST, first_manifest)
        plan_raw, plan_pin = _read_control_snapshot(plan_path, gate.MAX_META, first_plan)
        manifest, plan = gate._parse(manifest_raw), gate._parse(plan_raw)
        _manifest(manifest)
        report["family"], report["declared_files"] = manifest["family"], len(manifest["files"])
        _manifest_eligible(manifest)
        rows = _plan(plan, manifest["review_mode"])
        report["batch_count"] = len(rows)
        report["batches"] = [{"id": row["id"], "status": "NOT_RUN", "reason_codes": [],
                              "eligibility": None, "text_review": "NOT_RUN", "finding_count": 0}
                             for row in rows]
        _need(plan["manifest_sha256"] == manifest_pin[1], "MANIFEST_BINDING", "HOLD")
        _locations(manifest_path, plan_path, rows)
        code_pins = _code_snapshot()
        pins = (manifest_pin, plan_pin)
        control_pins, identities = _controls(rows, manifest_path, plan_path, code_pins, pins)
        phase = "receipts"
        snapshots, receipt_roots, held = {}, set(), False
        for item, child in zip(rows, report["batches"]):
            active = child
            snapshot = verifier._receipt_snapshot(item["receipt"])
            _need(snapshot["directory"][:2] not in receipt_roots, "CONTROL_LOCATION")
            receipt_roots.add(snapshot["directory"][:2])
            for pin in snapshot["pins"].values():
                _need(pin[:2] not in identities, "INPUT_INVALID")
                identities.add(pin[:2])
            snapshots[item["id"]] = snapshot
            _record_snapshot(report, child, snapshot)
            if snapshot["legacy"]:
                child["status"], child["reason_codes"] = "UNVERIFIABLE", ["LEGACY_RECEIPT"]
                raise CoverageIssue("UNVERIFIABLE", "LEGACY_RECEIPT")
            result = snapshot["result"]
            if result["eligibility"] != "ELIGIBLE_FOR_TEXT_REVIEW":
                child["status"], child["reason_codes"] = result["eligibility"], list(result["reason_codes"])
                held = True
            elif result["bindings"] is None:
                child["status"], child["reason_codes"] = "UNVERIFIABLE", ["ASSESSMENT_INCOMPLETE"]
                raise CoverageIssue("UNVERIFIABLE", "ASSESSMENT_INCOMPLETE")
        active = None
        _need(not held, "CHILD_ASSESSMENT_HOLD", "HOLD")
        phase = "coverage"
        union, policy, screen = {}, None, None
        for item in rows:
            result = snapshots[item["id"]]["result"]
            binding = result["bindings"]
            _need(result["family"] == manifest["family"], "FAMILY_MISMATCH", "HOLD")
            if policy is None:
                policy = binding["policy"]
            _need(binding["policy"] == policy, "POLICY_MISMATCH", "HOLD")
            _need((binding["screen"] is None) == (manifest["review_mode"] == "eligibility_only"),
                  "MODE_MISMATCH", "HOLD")
            if manifest["review_mode"] == "screened":
                if screen is None:
                    screen = binding["screen"]
                _need(binding["screen"] == screen, "SCREEN_MISMATCH", "HOLD")
            for record in binding["files"]:
                _need(record["path"] not in union, "COVERAGE_MISMATCH", "HOLD")
                union[record["path"]] = {key: value for key, value in record.items() if key != "mode"}
                report["covered_files"] = len(union)
                _need(len(union) <= MAX_FILES, "COVERAGE_MISMATCH", "HOLD")
        _need(sum(row["bytes"] for row in union.values()) <= MAX_TOTAL
              and [union[name] for name in sorted(union)] == manifest["files"], "COVERAGE_MISMATCH", "HOLD")
        phase = "control_capture"
        captured_controls = _capture_controls(rows, control_pins, snapshots, identities)
        phase = "inventory"
        inventories, directory_ids = {}, set(receipt_roots)
        for item in rows:
            observed = gate._inventory(item["candidate"])
            binding = snapshots[item["id"]]["result"]["bindings"]
            expected = {row["path"]: row for row in binding["files"]}
            _need(set(observed["files"]) == set(expected)
                  and sorted(observed["directories"]) == [row["path"] for row in binding["directories"]]
                  and all(pin[6] == expected[name]["bytes"] for name, pin in observed["files"].items()),
                  "CANDIDATE_CHANGED", "STALE")
            for pin in observed["directories"].values():
                _need(pin[:2] not in directory_ids, "CONTROL_LOCATION")
                directory_ids.add(pin[:2])
            for pin in observed["files"].values():
                _need(pin[:2] not in identities, "INPUT_INVALID")
                identities.add(pin[:2])
            inventories[item["id"]] = observed
        phase = "children"
        for item, child in zip(rows, report["batches"]):
            active = child
            response = verifier.verify(item["candidate"], item["proposal"], item["review"], item["receipt"],
                                       scanner_path=item["scanner"], private_terms_path=item["private_terms"])
            _child_response(report, child, response, len(snapshots[item["id"]]["result"]["bindings"]["files"]))
        active = None
        phase = "receipt_recheck"
        for item in rows:
            _need(verifier._receipt_snapshot(item["receipt"]) == snapshots[item["id"]], "RECEIPT_CHANGED", "STALE")
        phase = "input_recheck"
        _recheck_inputs(manifest_path, plan_path, pins)
        for path, (pin, maximum, trusted) in control_pins.items():
            raw, observed = gate._read_control(path, maximum, trusted_code=trusted, expected_pin=pin)
            _need((observed, gate._sha(raw)) == captured_controls[path], "INPUT_CHANGED", "STALE")
        phase = "code_recheck"
        _need(_code_snapshot() == code_pins, "CODE_CHANGED", "STALE")
        phase = "inventory_recheck"
        for item in rows:
            _need(gate._inventory(item["candidate"]) == inventories[item["id"]], "CANDIDATE_CHANGED", "STALE")
        report["bindings"] = {
            "format": "outlands-batch-coverage-bindings-v1", "manifest_sha256": manifest_pin[1],
            "plan_sha256": plan_pin[1], "policy": {key + "_sha256": value[1] for key, value in code_pins.items()},
            "batches": [{"id": item["id"], "receipt_files": dict(snapshots[item["id"]]["hashes"]),
                         "proposal_sha256": snapshots[item["id"]]["result"]["bindings"]["proposal_sha256"],
                         "review_sha256": snapshots[item["id"]]["result"]["bindings"]["review_sha256"],
                         "screen": snapshots[item["id"]]["result"]["bindings"]["screen"]} for item in rows]}
        report["status"] = "MATCHED"
    except CoverageIssue as error:
        report["status"], report["reason_codes"] = error.status, [error.code]
        if active is not None and active["status"] == "NOT_RUN":
            active["status"], active["reason_codes"] = error.status, [error.code]
    except verifier.VerificationIssue as error:
        if phase == "receipt_recheck":
            report["status"], report["reason_codes"] = "STALE", ["RECEIPT_CHANGED"]
        else:
            code = {"UNVERIFIABLE": "RECEIPT_INCOMPLETE", "STALE": "RECEIPT_CHANGED"}.get(error.status, "RECEIPT_INVALID")
            report["status"], report["reason_codes"] = error.status, [code]
        if active is not None:
            active["status"], active["reason_codes"] = report["status"], list(report["reason_codes"])
    except (gate.GateIssue, OSError, ValueError, TypeError, OverflowError, RecursionError) as error:
        if phase.endswith("recheck"):
            code = {"receipt_recheck": "RECEIPT_CHANGED", "input_recheck": "INPUT_CHANGED",
                    "code_recheck": "CODE_CHANGED", "inventory_recheck": "CANDIDATE_CHANGED"}[phase]
            report["status"], report["reason_codes"] = "STALE", [code]
        elif isinstance(error, OSError) and error.errno == errno.ENOENT:
            report["status"], report["reason_codes"] = "UNVERIFIABLE", ["RECEIPT_INCOMPLETE" if phase == "receipts" else "INPUT_UNAVAILABLE"]
        elif phase == "inventory":
            report["status"], report["reason_codes"] = "STALE", ["CANDIDATE_CHANGED"]
        elif phase == "control_capture" and isinstance(error, gate.GateIssue) and error.eligibility == "HOLD":
            report["status"], report["reason_codes"] = "STALE", ["INPUT_CHANGED"]
        else:
            report["reason_codes"] = ["RECEIPT_INVALID" if phase == "receipts" else "INPUT_INVALID"]
        if active is not None:
            active["status"], active["reason_codes"] = report["status"], list(report["reason_codes"])
    except Exception:
        report["reason_codes"] = ["INTERNAL_REFUSAL"]
        if active is not None:
            active["status"], active["reason_codes"] = "REFUSED", ["INTERNAL_REFUSAL"]
    if report["findings"]:
        report["text_review"] = "REVIEW"
    elif report["status"] == "MATCHED" and manifest["review_mode"] == "screened":
        report["text_review"] = "PASS"
    return report


def _summary(report):
    value = {key: item for key, item in report.items() if key not in {"findings", "batches", "bindings"}}
    value["format"] = "outlands-batch-coverage-cli-v1"
    value["finding_count"] = len(report["findings"])
    return value


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise CoverageIssue("REFUSED", "CLI_ARGUMENTS")


def main(argv=None):
    report = _result()
    try:
        parser = _Parser(prog="verify-batch-coverage", allow_abbrev=False, description=__doc__)
        parser.add_argument("--manifest", required=True)
        parser.add_argument("--plan", required=True)
        args = parser.parse_args(argv)
        report = verify_coverage(args.manifest, args.plan)
    except CoverageIssue as error:
        report["reason_codes"] = [error.code]
    print(json.dumps(_summary(report), sort_keys=True, separators=(",", ":")))
    return 2 if report["status"] == "REFUSED" else 0 if report["status"] == "MATCHED" and report["text_review"] != "REVIEW" else 1


if __name__ == "__main__":
    raise SystemExit(main())
