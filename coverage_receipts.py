"""Private unsigned coverage observations and read-only freshness checks.

Saved observations are not authenticated approvals or freshness-at-write tokens.
"""

import argparse
import errno
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys


_spec = importlib.util.spec_from_file_location(
    "outlands_receipts_coverage", Path(__file__).absolute().with_name("verify_batch_coverage.py"))
coverage = importlib.util.module_from_spec(_spec)
exec(compile(_spec.loader.get_source(_spec.name), _spec.origin, "exec"), coverage.__dict__)
gate = coverage.gate

MAX_RECORD = 24000000
PACKET_FILES = {"CLAIM.json", "record.json", "REVIEW.md", "REVIEW.txt", "COMPLETE.json"}
PRECEDING_FILES = PACKET_FILES - {"COMPLETE.json"}
REPORT_FIELDS = {"format", "status", "reason_codes", "family", "declared_files", "covered_files",
                 "batch_count", "verified_batches", "content_reads", "text_review", "scanner_called",
                 "findings", "batches", "bindings", "publication_status", "publication_authorized",
                 "export_performed", "destination_verified", "git_metadata_reviewed"}
COVERAGE_STATUSES = {"MATCHED", "HOLD", "STALE", "UNVERIFIABLE", "REFUSED"}
AUTHORITY_FIELDS = ("publication_authorized", "export_performed", "destination_verified", "git_metadata_reviewed")
CLAIM_RAW = b'{"format":"outlands-private-coverage-claim-v1","publication_authorized":false,"export_performed":false}\n'
REVIEW_RAW = (
    "# Private coverage observation\n\n"
    "Publication HELD. Authorization/export/destination/Git-review authority false. Licensing UNASSIGNED.\n\n"
    "This unsigned packet records one local point-in-time observation, not freshness at write, "
    "source completeness, authenticated human review, authorship, rights, confidentiality or release consent. "
    "Recorded findings and unqualified observations remain unqualified. "
    "Verification reads current explicit inputs without reassessment or rescreening. "
    "Owner-controlled coherent rewriting is not authenticated by these hashes. "
    "Trusted stable single-owner storage is assumed; sequential checks are not atomic multiwriter proof. "
    "Files are individually flushed and fsynced, without a crash-durability or producer-exit attestation. "
    "Separately recorded write/fsync/process/recorder uncertainty overrides later readable consistency. "
    "Partial evidence stays retained: no overwrite, repair, adoption, upgrade, cleanup or automatic retry. "
    "No candidate copy, scanner execution, provider, network, Git or publication action is performed.\n"
).encode("utf-8")


class ReceiptIssue(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status, self.code = status, code


def _need(condition, code="REPORT_INVALID", status="REFUSED"):
    if not condition:
        raise ReceiptIssue(status, code)


def _integer(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def _digest(value):
    return type(value) is str and gate.DIGEST.fullmatch(value) is not None


def _reasons(value, count):
    return (type(value) is list and len(value) == count
            and all(type(code) is str and gate.CODE.fullmatch(code) for code in value))


def _screen(value):
    return (value is None or (gate._exact(value, {"scanner_sha256", "private_terms_sha256"})
                             and value["scanner_sha256"] == gate.SCANNER_SHA256
                             and _digest(value["private_terms_sha256"])))


def _report_shape(report):
    _need(gate._exact(report, REPORT_FIELDS) and report["format"] == "outlands-batch-coverage-result-v1"
          and type(report["status"]) is str and report["status"] in COVERAGE_STATUSES
          and report["publication_status"] == "HELD" and report["scanner_called"] is False
          and all(report[key] is False for key in AUTHORITY_FIELDS))
    matched = report["status"] == "MATCHED"
    _need(_reasons(report["reason_codes"], 0 if matched else 1))
    _need(all(_integer(report[key], coverage.MAX_FILES) for key in ("declared_files", "covered_files", "content_reads"))
          and all(_integer(report[key], coverage.MAX_BATCHES) for key in ("batch_count", "verified_batches")))
    _need((report["family"] is None and report["declared_files"] == 0)
          or (type(report["family"]) is str and report["family"] in gate.FAMILIES and report["declared_files"] > 0))
    _need(report["family"] is not None or all(report[key] == 0 for key in
          ("covered_files", "content_reads", "batch_count", "verified_batches")))
    _need(type(report["text_review"]) is str and report["text_review"] in {"NOT_RUN", "PASS", "REVIEW"}
          and type(report["batches"]) is list and len(report["batches"]) == report["batch_count"])
    child_ids, grouped, verified = [], {}, 0
    for row in report["batches"]:
        _need(gate._exact(row, {"id", "status", "reason_codes", "eligibility", "text_review", "finding_count"})
              and type(row["id"]) is str and coverage.BATCH_ID.fullmatch(row["id"])
              and type(row["status"]) is str and row["status"] in COVERAGE_STATUSES | {"NOT_RUN"}
              and _reasons(row["reason_codes"], 0 if row["status"] in {"NOT_RUN", "MATCHED"} else 1)
              and (row["eligibility"] is None or (type(row["eligibility"]) is str
                   and row["eligibility"] in {"ELIGIBLE_FOR_TEXT_REVIEW", "HOLD", "REFUSED"}))
              and type(row["text_review"]) is str and row["text_review"] in {"NOT_RUN", "PASS", "REVIEW"}
              and _integer(row["finding_count"], gate.MAX_FILES * 32))
        _need((row["text_review"] == "REVIEW") == (row["finding_count"] > 0))
        _need(row["eligibility"] is not None or (row["text_review"] == "NOT_RUN" and row["finding_count"] == 0))
        if row["status"] == "MATCHED":
            _need(row["eligibility"] == "ELIGIBLE_FOR_TEXT_REVIEW")
            verified += 1
        child_ids.append(row["id"])
        grouped[row["id"]] = 0
    _need(child_ids == sorted(set(child_ids)) and verified == report["verified_batches"])
    _need(type(report["findings"]) is list and len(report["findings"]) <= coverage.MAX_BATCHES * gate.MAX_FILES * 32)
    for finding in report["findings"]:
        _need(gate._exact(finding, {"batch_id", "path", "check"}) and type(finding["batch_id"]) is str
              and finding["batch_id"] in grouped and type(finding["check"]) is str and gate.CODE.fullmatch(finding["check"]))
        gate._relative(finding["path"])
        grouped[finding["batch_id"]] += 1
    _need(all(grouped[row["id"]] == row["finding_count"] for row in report["batches"]))
    _need((report["text_review"] == "REVIEW") == bool(report["findings"]))
    if not matched:
        _need(report["bindings"] is None and report["text_review"] != "PASS")
        return
    _need(1 <= report["declared_files"] == report["covered_files"] == report["content_reads"]
          and 1 <= report["batch_count"] == report["verified_batches"] and report["family"] is not None
          and report["batch_count"] <= report["declared_files"] <= report["batch_count"] * gate.MAX_FILES)
    binding = report["bindings"]
    _need(gate._exact(binding, {"format", "manifest_sha256", "plan_sha256", "policy", "batches"})
          and binding["format"] == "outlands-batch-coverage-bindings-v1"
          and _digest(binding["manifest_sha256"]) and _digest(binding["plan_sha256"])
          and gate._exact(binding["policy"], {"gate_sha256", "verifier_sha256", "coverage_sha256"})
          and all(_digest(value) for value in binding["policy"].values())
          and type(binding["batches"]) is list and len(binding["batches"]) == len(child_ids))
    screens = []
    for row, child in zip(binding["batches"], report["batches"]):
        _need(gate._exact(row, {"id", "receipt_files", "proposal_sha256", "review_sha256", "screen"})
              and row["id"] == child["id"] and gate._exact(row["receipt_files"], coverage.verifier.RECEIPT_FILES)
              and all(_digest(value) for value in row["receipt_files"].values())
              and _digest(row["proposal_sha256"]) and _digest(row["review_sha256"]) and _screen(row["screen"]))
        _need(child["text_review"] == ("NOT_RUN" if row["screen"] is None else "REVIEW" if child["finding_count"] else "PASS"))
        screens.append(row["screen"])
    _need(all(value == screens[0] for value in screens))
    _need(report["text_review"] == ("REVIEW" if report["findings"] else "PASS" if screens[0] is not None else "NOT_RUN"))


def _validate_report(report):
    """Validate a full bounded observation, without opening any candidate."""
    try:
        _report_shape(report)
    except ReceiptIssue:
        raise
    except (gate.GateIssue, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise ReceiptIssue("REFUSED", "REPORT_INVALID") from None


def _validate_record(record):
    _need(gate._exact(record, {"format", "inputs", "policy", "report"})
          and record["format"] == "outlands-private-coverage-record-v1"
          and gate._exact(record["inputs"], {"manifest_sha256", "plan_sha256"})
          and all(_digest(value) for value in record["inputs"].values())
          and gate._exact(record["policy"], {"receipts_sha256"}) and _digest(record["policy"]["receipts_sha256"]),
          "PACKET_INVALID")
    _validate_report(record["report"])
    if record["report"]["status"] == "MATCHED":
        binding = record["report"]["bindings"]
        _need(all(binding[key] == value for key, value in record["inputs"].items()), "PACKET_INVALID")


def _policy_snapshot(*, expected_pin=None):
    raw, pin = gate._read_control(gate._absolute(__file__), gate.MAX_META, trusted_code=True, expected_pin=expected_pin)
    return pin, gate._sha(raw)


def _context(manifest_path, plan_path, receipt_path, forbidden_ids=()):
    manifest_path, plan_path, receipt_path = map(gate._absolute, (manifest_path, plan_path, receipt_path))
    _need(manifest_path != plan_path, "CONTROL_LOCATION")
    raw_manifest, manifest_pin = gate._read_control(manifest_path, coverage.MAX_MANIFEST, forbidden_ids=forbidden_ids)
    raw_plan, plan_pin = gate._read_control(plan_path, gate.MAX_META, forbidden_ids=set(forbidden_ids) | {manifest_pin[:2]})
    manifest, plan = gate._parse(raw_manifest), gate._parse(raw_plan)
    coverage._manifest(manifest)
    rows = coverage._plan(plan, manifest["review_mode"])
    coverage._locations(manifest_path, plan_path, rows)
    controls = [manifest_path, plan_path] + [row[key] for row in rows for key in ("proposal", "review")]
    controls += [row[key] for row in rows for key in ("scanner", "private_terms") if row[key] is not None]
    roots = [row[key] for row in rows for key in ("candidate", "receipt")]
    own = gate._absolute(__file__)
    code = list(coverage._fixed_paths().values()) + [own]
    _need(own not in controls and not any(gate._inside(own, root) for root in roots), "CONTROL_LOCATION")
    _need(not any(gate._inside(receipt_path, root) or gate._inside(root, receipt_path) for root in roots)
          and not any(gate._inside(path, receipt_path) or gate._inside(receipt_path, path) for path in controls + code),
          "CONTROL_LOCATION")
    policy = _policy_snapshot()
    _need(policy[0][:2] not in set(forbidden_ids) | {manifest_pin[:2], plan_pin[:2]}, "CONTROL_LOCATION")
    return {"manifest_path": manifest_path, "plan_path": plan_path, "receipt_path": receipt_path,
            "manifest": manifest, "plan": plan, "rows": rows,
            "inputs": ((manifest_pin, gate._sha(raw_manifest)), (plan_pin, gate._sha(raw_plan))), "policy": policy}


def _recheck_context(context):
    coverage._recheck_inputs(context["manifest_path"], context["plan_path"], context["inputs"])
    _need(_policy_snapshot(expected_pin=context["policy"][0]) == context["policy"], "POLICY_CHANGED", "STALE")


def _parent(path):
    fd = gate._open_dir(path.parent)
    try:
        pin = gate._identity(gate._private_dir(fd))
        try:
            os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return fd, pin
        raise ReceiptIssue("REFUSED", "PACKET_EXISTS")
    except BaseException:
        os.close(fd)
        raise


def _same_parent(path, fd, expected):
    named = gate._open_dir(path.parent)
    try:
        current = gate._identity(gate._private_dir(fd))
        _need(current[:5] == expected[:5] and current == gate._identity(gate._private_dir(named)), "PACKET_UNAVAILABLE")
    finally:
        os.close(named)


def _write_new(fd, name, raw):
    out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        info = os.fstat(out)
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
              and stat.S_IMODE(info.st_mode) == 0o600, "PACKET_UNAVAILABLE")
        with os.fdopen(out, "wb", closefd=False) as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(out)


def _packet_snapshot(path):
    fd = gate._open_dir(path)
    try:
        before = gate._identity(gate._private_dir(fd))
        names = set()
        with os.scandir(fd) as entries:
            for entry in entries:
                names.add(entry.name)
                _need(len(names) <= 5, "PACKET_INVALID")
        foreign = names in (coverage.verifier.RECEIPT_FILES, coverage.verifier.LEGACY_FILES)
        if foreign:
            coverage.verifier._receipt_snapshot(path)
            raise ReceiptIssue("UNVERIFIABLE", "FOREIGN_PACKET")
        _need(not names - PACKET_FILES, "PACKET_INVALID")
        _need(names == PACKET_FILES, "PACKET_INCOMPLETE", "UNVERIFIABLE")
        limits = {"CLAIM.json": 1024, "record.json": MAX_RECORD, "REVIEW.md": 16384,
                  "REVIEW.txt": 16384, "COMPLETE.json": 4096}
        raw, pins = {}, {}
        for name in sorted(names):
            raw[name], pins[name] = gate._read_at(fd, name, limits[name], {0o600})
        _need(len({pin[:2] for pin in pins.values()}) == len(pins), "PACKET_INVALID")
        _need(gate._identity(os.fstat(fd)) == before, "PACKET_CHANGED", "STALE")
        named = gate._open_dir(path)
        try:
            _need(gate._identity(gate._private_dir(named)) == before, "PACKET_CHANGED", "STALE")
        finally:
            os.close(named)
        claim, complete = gate._parse(raw["CLAIM.json"]), gate._parse(raw["COMPLETE.json"])
        _need(gate._exact(claim, {"format", "publication_authorized", "export_performed"})
              and claim["format"] == "outlands-private-coverage-claim-v1"
              and claim["publication_authorized"] is False and claim["export_performed"] is False, "PACKET_INVALID")
        _need(gate._exact(complete, {"format", "files"}) and complete["format"] == "outlands-private-coverage-complete-v1"
              and gate._exact(complete["files"], PRECEDING_FILES)
              and all(_digest(complete["files"][name]) and complete["files"][name] == gate._sha(raw[name])
                      for name in PRECEDING_FILES), "PACKET_INVALID")
        _need(raw["REVIEW.md"] == raw["REVIEW.txt"] == REVIEW_RAW, "PACKET_INVALID")
        record = gate._parse(raw["record.json"])
        _validate_record(record)
        return {"directory": before, "pins": pins, "hashes": {name: gate._sha(value) for name, value in raw.items()}, "record": record}
    finally:
        os.close(fd)


def _save_summary():
    return {"format": "outlands-private-coverage-save-v1", "status": "REFUSED", "reason_codes": [],
            "coverage_status": None, "text_review": "NOT_RUN", "finding_count": 0, "content_reads": 0,
            "scanner_called": False, "publication_status": "HELD", **{key: False for key in AUTHORITY_FIELDS}}


def _verify_summary():
    return {"format": "outlands-private-coverage-verification-v1", "status": "REFUSED",
            "integrity": "NOT_CHECKED", "freshness": "NOT_CHECKED", "reason_codes": [], "saved_status": None,
            "text_review": "NOT_RUN", "finding_count": 0, "content_reads": 0, "scanner_called": False,
            "publication_status": "HELD", **{key: False for key in AUTHORITY_FIELDS}}


def _observation(summary, report, key):
    summary[key] = report["status"]
    summary["text_review"] = report["text_review"]
    summary["finding_count"] = len(report["findings"])


def _json_raw(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def save_coverage(manifest_path, plan_path, receipt_path):
    summary, parent, packet = _save_summary(), None, None
    try:
        context = _context(manifest_path, plan_path, receipt_path)
        parent, parent_pin = _parent(context["receipt_path"])
        report = coverage.verify_coverage(context["manifest_path"], context["plan_path"])
        _validate_report(report)
        _observation(summary, report, "coverage_status")
        summary["content_reads"] = report["content_reads"]
        inputs = {"manifest_sha256": context["inputs"][0][1], "plan_sha256": context["inputs"][1][1]}
        record = {"format": "outlands-private-coverage-record-v1", "inputs": inputs,
                  "policy": {"receipts_sha256": context["policy"][1]}, "report": report}
        _validate_record(record)
        _recheck_context(context)
        record_raw = _json_raw(record)
        _need(len(record_raw) <= MAX_RECORD, "REPORT_INVALID")
        _same_parent(context["receipt_path"], parent, parent_pin)
        os.mkdir(context["receipt_path"].name, 0o700, dir_fd=parent)
        packet = os.open(context["receipt_path"].name, gate.DIR_FLAGS, dir_fd=parent)
        gate._private_dir(packet)
        buffers = {"CLAIM.json": CLAIM_RAW, "record.json": record_raw, "REVIEW.md": REVIEW_RAW, "REVIEW.txt": REVIEW_RAW}
        for name in ("CLAIM.json", "record.json", "REVIEW.md", "REVIEW.txt"):
            _write_new(packet, name, buffers[name])
        _recheck_context(context)
        _same_parent(context["receipt_path"], parent, parent_pin)
        named = gate._open_dir(context["receipt_path"])
        try:
            _need(gate._identity(gate._private_dir(packet)) == gate._identity(gate._private_dir(named)), "PACKET_UNAVAILABLE")
        finally:
            os.close(named)
        complete = {"format": "outlands-private-coverage-complete-v1", "files": {name: gate._sha(raw) for name, raw in buffers.items()}}
        _write_new(packet, "COMPLETE.json", _json_raw(complete))
        summary["status"] = "SAVED"
    except ReceiptIssue as error:
        summary["reason_codes"] = [error.code]
    except gate.GateIssue as error:
        summary["reason_codes"] = ["INPUT_CHANGED" if error.eligibility == "HOLD" else "INPUT_INVALID"]
    except (coverage.CoverageIssue, OSError, ValueError, TypeError, OverflowError, RecursionError):
        summary["reason_codes"] = ["INPUT_INVALID" if parent is None else "PACKET_UNAVAILABLE"]
    except Exception:
        summary["reason_codes"] = ["INTERNAL_REFUSAL"]
    finally:
        for fd in (packet, parent):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    summary["status"], summary["reason_codes"] = "REFUSED", ["PACKET_UNAVAILABLE"]
    return summary


def _capture_state(context, packet):
    report = packet["record"]["report"]
    code = coverage._code_snapshot()
    _need({key + "_sha256": value[1] for key, value in code.items()} == report["bindings"]["policy"], "CODE_CHANGED", "STALE")
    rows = context["rows"]
    _need([row["id"] for row in rows] == [row["id"] for row in report["batches"]]
          and context["manifest"]["family"] == report["family"]
          and len(context["manifest"]["files"]) == report["declared_files"], "PACKET_INVALID")
    controls, identities = coverage._controls(rows, context["manifest_path"], context["plan_path"], code, context["inputs"])
    packet_ids = {pin[:2] for pin in packet["pins"].values()} | {context["policy"][0][:2]}
    _need(not identities & packet_ids and len(packet_ids) == 6, "CONTROL_LOCATION")
    identities.update(packet_ids)
    snapshots, roots, findings, union = {}, {packet["directory"][:2]}, [], {}
    for row, saved, binding in zip(rows, report["batches"], report["bindings"]["batches"]):
        snapshot = coverage.verifier._receipt_snapshot(row["receipt"])
        _need(snapshot["hashes"] == binding["receipt_files"], "CHILD_CHANGED", "STALE")
        result = snapshot["result"]
        _need(not snapshot["legacy"] and result["eligibility"] == "ELIGIBLE_FOR_TEXT_REVIEW" and result["bindings"] is not None, "PACKET_INVALID")
        _need(snapshot["directory"][:2] not in roots, "CONTROL_LOCATION")
        roots.add(snapshot["directory"][:2])
        for pin in snapshot["pins"].values():
            _need(pin[:2] not in identities, "CONTROL_LOCATION")
            identities.add(pin[:2])
        actual = result["bindings"]
        _need(saved["eligibility"] == result["eligibility"] and saved["text_review"] == result["text_review"]
              and saved["finding_count"] == len(result["findings"])
              and binding["proposal_sha256"] == actual["proposal_sha256"] and binding["review_sha256"] == actual["review_sha256"]
              and binding["screen"] == actual["screen"] and result["family"] == report["family"]
              and actual["policy"]["engine_sha256"] == code["gate"][1], "PACKET_INVALID")
        findings.extend({"batch_id": row["id"], **item} for item in result["findings"])
        for item in actual["files"]:
            _need(item["path"] not in union, "PACKET_INVALID")
            union[item["path"]] = {key: value for key, value in item.items() if key != "mode"}
        snapshots[row["id"]] = snapshot
    _need(findings == report["findings"] and [union[name] for name in sorted(union)] == context["manifest"]["files"], "PACKET_INVALID")
    captured = coverage._capture_controls(rows, controls, snapshots, identities)
    inventories = {}
    for row in rows:
        observed = gate._inventory(row["candidate"])
        binding = snapshots[row["id"]]["result"]["bindings"]
        expected = {item["path"]: item for item in binding["files"]}
        _need(set(observed["files"]) == set(expected)
              and sorted(observed["directories"]) == [item["path"] for item in binding["directories"]]
              and all(pin[6] == expected[name]["bytes"] for name, pin in observed["files"].items()), "CANDIDATE_CHANGED", "STALE")
        for pin in observed["directories"].values():
            _need(pin[:2] not in roots, "CONTROL_LOCATION")
            roots.add(pin[:2])
        for pin in observed["files"].values():
            _need(pin[:2] not in identities, "CONTROL_LOCATION")
            identities.add(pin[:2])
        inventories[row["id"]] = observed
    return {"code": code, "controls": controls, "captured": captured, "snapshots": snapshots, "inventories": inventories}


def _recheck_state(context, state):
    _recheck_context(context)
    for path, (pin, maximum, trusted) in state["controls"].items():
        raw, observed = gate._read_control(path, maximum, trusted_code=trusted, expected_pin=pin)
        _need((observed, gate._sha(raw)) == state["captured"][path], "INPUT_CHANGED", "STALE")
    for row in context["rows"]:
        _need(coverage.verifier._receipt_snapshot(row["receipt"]) == state["snapshots"][row["id"]], "CHILD_CHANGED", "STALE")
    _need(coverage._code_snapshot() == state["code"], "CODE_CHANGED", "STALE")
    for row in context["rows"]:
        _need(gate._inventory(row["candidate"]) == state["inventories"][row["id"]], "CANDIDATE_CHANGED", "STALE")
    _need(_policy_snapshot(expected_pin=context["policy"][0]) == context["policy"], "POLICY_CHANGED", "STALE")


def verify_receipt(manifest_path, plan_path, receipt_path):
    summary, phase = _verify_summary(), "packet"
    try:
        path = gate._absolute(receipt_path)
        packet = _packet_snapshot(path)
        report = packet["record"]["report"]
        summary["integrity"] = "MATCHED"
        _observation(summary, report, "saved_status")
        phase = "freshness"
        _need(report["status"] == "MATCHED", "SAVED_UNQUALIFIED", "UNVERIFIABLE")
        context = _context(manifest_path, plan_path, path, {pin[:2] for pin in packet["pins"].values()})
        _need(packet["record"]["inputs"] == {"manifest_sha256": context["inputs"][0][1], "plan_sha256": context["inputs"][1][1]}, "INPUT_CHANGED", "STALE")
        _need(packet["record"]["policy"]["receipts_sha256"] == context["policy"][1], "POLICY_CHANGED", "STALE")
        _need(context["plan"]["manifest_sha256"] == context["inputs"][0][1], "PACKET_INVALID")
        state = _capture_state(context, packet)
        current = coverage.verify_coverage(context["manifest_path"], context["plan_path"])
        if type(current) is dict and _integer(current.get("content_reads"), coverage.MAX_FILES):
            summary["content_reads"] = current["content_reads"]
        _validate_report(current)
        if current["status"] != "MATCHED":
            status = "UNVERIFIABLE" if current["status"] == "HOLD" else current["status"]
            raise ReceiptIssue(status, "CURRENT_UNQUALIFIED")
        _need(current == report, "REPORT_CHANGED", "STALE")
        phase = "packet_recheck"
        _need(_packet_snapshot(path) == packet, "PACKET_CHANGED", "STALE")
        phase = "state_recheck"
        _recheck_state(context, state)
        summary["status"], summary["freshness"] = "MATCHED", "MATCHED"
    except ReceiptIssue as error:
        if phase == "packet_recheck":
            summary["status"], summary["integrity"], summary["freshness"] = "STALE", "STALE", "STALE"
            summary["reason_codes"] = ["PACKET_CHANGED"]
        else:
            summary["status"], summary["reason_codes"] = error.status, [error.code]
            summary["integrity" if phase == "packet" else "freshness"] = error.status
    except coverage.verifier.VerificationIssue as error:
        if phase in {"packet_recheck", "state_recheck"}:
            summary["status"], summary["freshness"], summary["reason_codes"] = "STALE", "STALE", ["PACKET_CHANGED" if phase == "packet_recheck" else "CHILD_CHANGED"]
            if phase == "packet_recheck":
                summary["integrity"] = "STALE"
        else:
            codes = ({"UNVERIFIABLE": "PACKET_INCOMPLETE", "STALE": "PACKET_CHANGED"}
                     if phase == "packet" else {"UNVERIFIABLE": "CHILD_UNVERIFIABLE", "STALE": "CHILD_CHANGED"})
            code = codes.get(error.status, "PACKET_INVALID" if phase == "packet" else "INPUT_INVALID")
            summary["status"], summary["reason_codes"] = error.status, [code]
            summary["integrity" if phase == "packet" else "freshness"] = error.status
    except coverage.CoverageIssue as error:
        if phase in {"packet_recheck", "state_recheck"}:
            summary["status"], summary["freshness"] = "STALE", "STALE"
            summary["reason_codes"] = ["PACKET_CHANGED" if phase == "packet_recheck" else "INPUT_CHANGED"]
            if phase == "packet_recheck":
                summary["integrity"] = "STALE"
        else:
            mappings = {"STALE": ("STALE", "INPUT_CHANGED"),
                        "UNVERIFIABLE": ("UNVERIFIABLE", "INPUT_UNAVAILABLE"),
                        "REFUSED": ("REFUSED", "INPUT_INVALID"),
                        "HOLD": ("UNVERIFIABLE", "CURRENT_UNQUALIFIED")}
            status, code = mappings.get(error.status, ("REFUSED", "INTERNAL_REFUSAL"))
            summary["status"], summary["reason_codes"] = status, [code]
            summary["integrity" if phase == "packet" else "freshness"] = status
    except (gate.GateIssue, OSError,
            ValueError, TypeError, OverflowError, RecursionError) as error:
        if phase in {"packet_recheck", "state_recheck"}:
            summary["status"], summary["freshness"] = "STALE", "STALE"
            summary["reason_codes"] = ["PACKET_CHANGED" if phase == "packet_recheck" else "INPUT_CHANGED"]
            if phase == "packet_recheck":
                summary["integrity"] = "STALE"
        elif isinstance(error, OSError) and error.errno == errno.ENOENT:
            summary["status"], summary["reason_codes"] = "UNVERIFIABLE", ["PACKET_INCOMPLETE" if phase == "packet" else "INPUT_UNAVAILABLE"]
            summary["integrity" if phase == "packet" else "freshness"] = "UNVERIFIABLE"
        elif isinstance(error, gate.GateIssue) and error.eligibility == "HOLD":
            summary["status"], summary["reason_codes"] = "STALE", ["PACKET_CHANGED" if phase == "packet" else "INPUT_CHANGED"]
            summary["integrity" if phase == "packet" else "freshness"] = "STALE"
        else:
            summary["reason_codes"] = ["PACKET_INVALID" if phase == "packet" else "INPUT_INVALID"]
            summary["integrity" if phase == "packet" else "freshness"] = "REFUSED"
    except Exception:
        summary["reason_codes"] = ["INTERNAL_REFUSAL"]
        summary["integrity" if phase == "packet" else "freshness"] = "REFUSED"
    return summary


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ReceiptIssue("REFUSED", "CLI_ARGUMENTS")


def main(argv=None):
    os.umask(0o077)
    arguments = sys.argv[1:] if argv is None else argv
    operation = arguments[0] if arguments and arguments[0] in {"save", "verify"} else None
    summary = _verify_summary() if operation == "verify" else _save_summary()
    try:
        parser = _Parser(prog="private-coverage-receipts", allow_abbrev=False, description=__doc__)
        commands = parser.add_subparsers(dest="operation", required=True, parser_class=_Parser)
        for name in ("save", "verify"):
            command = commands.add_parser(name, allow_abbrev=False)
            for flag in ("manifest", "plan", "receipt"):
                command.add_argument("--" + flag, required=True)
        args = parser.parse_args(arguments)
        operation = args.operation
        summary = save_coverage(args.manifest, args.plan, args.receipt) if operation == "save" else verify_receipt(args.manifest, args.plan, args.receipt)
    except ReceiptIssue as error:
        summary = _verify_summary() if operation == "verify" else _save_summary()
        summary["reason_codes"] = [error.code]
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    if summary["status"] == "REFUSED":
        return 2
    matched = summary["status"] == "MATCHED" or (summary["status"] == "SAVED" and summary["coverage_status"] == "MATCHED")
    return 0 if matched and summary["text_review"] != "REVIEW" else 1


if __name__ == "__main__":
    raise SystemExit(main())
