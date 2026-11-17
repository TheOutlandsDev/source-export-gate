"""Read-only consistency checks for unsigned private Source Export Gate receipts.

A match does not authenticate a receipt, rerun its screen, or grant authority.
"""

import argparse
import errno
import importlib.util
import json
import os
from pathlib import Path


# Isolated Python omits the script directory. Load only this fixed trusted sibling.
_spec = importlib.util.spec_from_file_location(
    "outlands_receipt_gate", Path(__file__).absolute().with_name("source_export_gate.py"))
gate = importlib.util.module_from_spec(_spec)
# Read source directly, ignoring bytecode caches and never writing them, even if
# a library caller did not select Python's -B option.
exec(compile(_spec.loader.get_source(_spec.name), _spec.origin, "exec"), gate.__dict__)


MAX_RESULT = 2000000
MAX_NOTE = 16384
RECEIPT_FILES = {"CLAIM.json", "REVIEW.md", "REVIEW.txt", "result.json", "COMPLETE.json"}
LEGACY_FILES = RECEIPT_FILES - {"COMPLETE.json"}
RESULT_FIELDS = {"format", "eligibility", "reason_codes", "family", "proposed_files",
                 "observed_files", "content_reads", "scanner_called", "text_review",
                 "findings", "publication_status", "publication_authorized", "export_performed",
                 "destination_verified", "git_metadata_reviewed"}
AUTHORITY_FIELDS = ("publication_authorized", "export_performed", "destination_verified",
                    "git_metadata_reviewed")


class VerificationIssue(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status, self.code = status, code


def _require(condition, code="RECEIPT_INVALID", status="REFUSED"):
    if not condition:
        raise VerificationIssue(status, code)


def _summary():
    return {"format": "outlands-source-export-verification-v1", "status": "REFUSED",
            "reason_codes": [], "content_reads": 0, "scanner_called": False,
            "publication_status": "HELD", "publication_authorized": False,
            "export_performed": False, "destination_verified": False,
            "git_metadata_reviewed": False}


def _digest(value):
    return type(value) is str and gate.DIGEST.fullmatch(value) is not None


def _integer(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def _bindings_valid(value):
    _require(gate._exact(value, {"format", "policy", "proposal_sha256", "review_sha256",
                                 "files", "directories", "screen"})
             and value["format"] == "outlands-source-export-bindings-v1")
    policy = value["policy"]
    _require(gate._exact(policy, {"id", "engine_sha256"})
             and policy["id"] == gate.POLICY_ID and _digest(policy["engine_sha256"])
             and _digest(value["proposal_sha256"]) and _digest(value["review_sha256"]))
    files = value["files"]
    _require(type(files) is list and 1 <= len(files) <= gate.MAX_FILES)
    names, directories, total = [], {""}, 0
    for row in files:
        _require(gate._exact(row, {"path", "sha256", "bytes", "mode", "artifact_kind",
                                   "synthetic_fixture"}))
        parts = gate._relative(row["path"])
        _require(gate._path_eligible(row["path"]) and _digest(row["sha256"])
                 and _integer(row["bytes"], gate.MAX_FILE) and row["mode"] == "0600"
                 and type(row["artifact_kind"]) is str
                 and row["artifact_kind"] in gate.ELIGIBLE_KINDS
                 and type(row["synthetic_fixture"]) is bool
                 and (row["artifact_kind"] != "synthetic_example" or row["synthetic_fixture"] is True))
        names.append(row["path"])
        total += row["bytes"]
        directories.update("/".join(parts[:i]) for i in range(1, len(parts)))
    _require(names == sorted(set(names)) and total <= gate.MAX_TOTAL)
    rows = value["directories"]
    _require(type(rows) is list and 1 <= len(rows) <= gate.MAX_ENTRIES + 1)
    directory_names = []
    for row in rows:
        _require(gate._exact(row, {"path", "mode"}) and type(row["path"]) is str
                 and row["mode"] == "0700")
        if row["path"]:
            gate._relative(row["path"])
        directory_names.append(row["path"])
    _require(directory_names == sorted(directories)
             and len(files) + len(rows) - 1 <= gate.MAX_ENTRIES)
    screen = value["screen"]
    _require(screen is None or (gate._exact(screen, {"scanner_sha256", "private_terms_sha256"})
                               and _digest(screen["scanner_sha256"])
                               and screen["scanner_sha256"] == gate.SCANNER_SHA256
                               and _digest(screen["private_terms_sha256"])))


def _result_valid(value, legacy=False):
    fields = RESULT_FIELDS if legacy else RESULT_FIELDS | {"bindings"}
    _require(gate._exact(value, fields)
             and value["format"] == "outlands-source-export-result-v" + ("1" if legacy else "2")
             and type(value["eligibility"]) is str
             and value["eligibility"] in {"ELIGIBLE_FOR_TEXT_REVIEW", "HOLD", "REFUSED"}
             and value["publication_status"] == "HELD"
             and all(value[key] is False for key in AUTHORITY_FIELDS))
    reasons = value["reason_codes"]
    _require(type(reasons) is list and len(reasons) <= 1
             and all(type(code) is str and gate.CODE.fullmatch(code) for code in reasons))
    _require(all(_integer(value[key], gate.MAX_FILES) for key in
                 ("proposed_files", "observed_files", "content_reads"))
             and value["content_reads"] <= value["proposed_files"]
             and type(value["scanner_called"]) is bool
             and type(value["text_review"]) is str
             and value["text_review"] in {"NOT_RUN", "PASS", "REVIEW"})
    family = value["family"]
    _require((family is None and value["proposed_files"] == 0)
             or (type(family) is str and family in gate.FAMILIES and value["proposed_files"] > 0))
    _require(family is not None or value["observed_files"] == value["content_reads"] == 0)
    findings = value["findings"]
    _require(type(findings) is list and len(findings) <= gate.MAX_FILES * 32)
    for finding in findings:
        _require(gate._exact(finding, {"path", "check"})
                 and type(finding["check"]) is str and gate.CODE.fullmatch(finding["check"]))
        gate._relative(finding["path"])
    text = value["text_review"]
    _require((text == "NOT_RUN" and not findings)
             or (text == "PASS" and value["scanner_called"] and not findings)
             or (text == "REVIEW" and value["scanner_called"] and bool(findings)))
    _require(not value["scanner_called"]
             or (value["proposed_files"] == value["observed_files"] == value["content_reads"] > 0))
    complete = value["eligibility"] == "ELIGIBLE_FOR_TEXT_REVIEW"
    if complete:
        _require(not reasons and family is not None
                 and value["proposed_files"] == value["observed_files"] == value["content_reads"]
                 and value["scanner_called"] == (text != "NOT_RUN"))
    else:
        _require(len(reasons) == 1)
    if not legacy:
        bindings = value["bindings"]
        if bindings is not None:
            _bindings_valid(bindings)
            _require(complete and len(bindings["files"]) == value["proposed_files"]
                     and (bindings["screen"] is not None) == value["scanner_called"]
                     and all(item["path"] in {row["path"] for row in bindings["files"]}
                             for item in findings))


def _receipt_snapshot(path):
    """Read a finite exact receipt set without following a member or directory link."""
    fd = gate._open_dir(path)
    try:
        before = gate._identity(gate._private_dir(fd))
        names = set()
        with os.scandir(fd) as entries:
            for entry in entries:
                names.add(entry.name)
                _require(len(names) <= len(RECEIPT_FILES))
        _require(not names - RECEIPT_FILES)
        _require(names in (RECEIPT_FILES, LEGACY_FILES), "RECEIPT_INCOMPLETE", "UNVERIFIABLE")
        limits = {"CLAIM.json": 1024, "REVIEW.md": MAX_NOTE, "REVIEW.txt": MAX_NOTE,
                  "result.json": MAX_RESULT, "COMPLETE.json": 4096}
        raw, pins = {}, {}
        for name in sorted(names):
            raw[name], pins[name] = gate._read_at(fd, name, limits[name], {0o600})
        _require(gate._identity(os.fstat(fd)) == before, "RECEIPT_CHANGED", "STALE")
        named = gate._open_dir(path)
        try:
            _require(gate._identity(gate._private_dir(named)) == before,
                     "RECEIPT_CHANGED", "STALE")
        finally:
            os.close(named)
        claim = gate._parse(raw["CLAIM.json"])
        legacy = names == LEGACY_FILES
        if legacy and type(claim) is dict and claim.get("format") == "outlands-source-export-claim-v2":
            _require(gate._exact(claim, {"format", "publication_authorized", "export_performed"})
                     and claim["publication_authorized"] is False and claim["export_performed"] is False)
            raise VerificationIssue("UNVERIFIABLE", "RECEIPT_INCOMPLETE")
        _require(gate._exact(claim, {"format", "publication_authorized", "export_performed"})
                 and claim["format"] == "outlands-source-export-claim-v" + ("1" if legacy else "2")
                 and claim["publication_authorized"] is False and claim["export_performed"] is False)
        _require(0 < len(raw["REVIEW.md"]) <= MAX_NOTE and raw["REVIEW.md"] == raw["REVIEW.txt"])
        note = raw["REVIEW.md"].decode("utf-8")
        _require("\x00" not in note)
        result = gate._parse(raw["result.json"])
        _result_valid(result, legacy)
        if not legacy:
            complete = gate._parse(raw["COMPLETE.json"])
            _require(gate._exact(complete, {"format", "files"})
                     and complete["format"] == "outlands-source-export-complete-v1"
                     and gate._exact(complete["files"], LEGACY_FILES)
                     and all(_digest(complete["files"][name])
                             and complete["files"][name] == gate._sha(raw[name])
                             for name in LEGACY_FILES))
        return {"directory": before, "pins": pins, "hashes": {name: gate._sha(value) for name, value in raw.items()},
                "result": result, "legacy": legacy}
    finally:
        os.close(fd)


def _terms_valid(raw):
    value = gate._parse(raw)
    _require(gate._exact(value, {"schema_version", "terms"})
             and type(value["schema_version"]) is int and value["schema_version"] == 1
             and type(value["terms"]) is list and 1 <= len(value["terms"]) <= 64,
             "INPUT_INVALID")
    terms = value["terms"]
    _require(all(type(term) is str and 4 <= len(term) <= 128
                 and all(ord(char) >= 32 for char in term) for term in terms)
             and len({term.casefold() for term in terms}) == len(terms), "INPUT_INVALID")


def verify(candidate_root, proposal_path, review_path, receipt_path, *,
           scanner_path=None, private_terms_path=None):
    """Compare captured bindings to current inputs; never execute an assessment."""
    summary, root_fd, phase = _summary(), None, "arguments"
    try:
        candidate, receipt = gate._absolute(candidate_root), gate._absolute(receipt_path)
        proposal_path, review_path = gate._absolute(proposal_path), gate._absolute(review_path)
        _require((scanner_path is None) == (private_terms_path is None), "SCANNER_ARGUMENTS")
        controls = [proposal_path, review_path]
        if scanner_path is not None:
            scanner_path, private_terms_path = gate._absolute(scanner_path), gate._absolute(private_terms_path)
            controls.extend((scanner_path, private_terms_path))
        _require(len(set(controls)) == len(controls)
                 and not gate._inside(receipt, candidate) and not gate._inside(candidate, receipt)
                 and not any(gate._inside(path, candidate) or gate._inside(path, receipt) for path in controls),
                 "INPUT_INVALID")
        policy_path = gate._absolute(gate.__file__)
        _require(not gate._inside(policy_path, candidate) and policy_path not in controls,
                 "INPUT_INVALID")
        phase = "receipt"
        evidence = _receipt_snapshot(receipt)
        _require(not evidence["legacy"], "LEGACY_RECEIPT", "UNVERIFIABLE")
        result = evidence["result"]
        _require(result["eligibility"] == "ELIGIBLE_FOR_TEXT_REVIEW" and result["bindings"] is not None,
                 "ASSESSMENT_INCOMPLETE", "UNVERIFIABLE")
        bindings = result["bindings"]
        screen = bindings["screen"]
        _require(screen is not None or scanner_path is None, "SCANNER_ARGUMENTS")
        _require(screen is None or scanner_path is not None, "SCANNER_REQUIRED", "UNVERIFIABLE")
        receipt_ids = {pin[:2] for pin in evidence["pins"].values()}
        phase = "controls"
        policy = gate._policy_snapshot()
        _require(policy[1] == bindings["policy"]["engine_sha256"], "POLICY_CHANGED", "STALE")
        control_forbidden = receipt_ids | {policy[0][:2]}
        proposal_raw, proposal_pin = gate._read_control(proposal_path, forbidden_ids=control_forbidden)
        review_raw, review_pin = gate._read_control(review_path, forbidden_ids=control_forbidden | {proposal_pin[:2]})
        proposal, review = gate._parse(proposal_raw), gate._parse(review_raw)
        gate._proposal(proposal)
        gate._review(review)
        pins = ((proposal_pin, gate._sha(proposal_raw)), (review_pin, gate._sha(review_raw)))
        _require(pins[0][1] == bindings["proposal_sha256"] and pins[1][1] == bindings["review_sha256"],
                 "INPUT_CHANGED", "STALE")
        # These controls are the recorded raw buffers. Contradictions are invalid
        # evidence, rather than drift, and must fail before reading candidate bytes.
        _require(bindings["files"] == [dict(row, mode="0600") for row in proposal["files"]])
        _require(proposal["family"] == result["family"] and len(proposal["files"]) == result["proposed_files"],
                 "RECEIPT_INVALID")
        try:
            gate._eligible(proposal, review, pins[0][1])
        except gate.GateIssue:
            raise VerificationIssue("REFUSED", "RECEIPT_INVALID") from None
        phase = "candidate"
        observed = gate._inventory(candidate)
        expected = {row["path"]: row for row in bindings["files"]}
        _require(set(observed["files"]) == set(expected)
                 and sorted(observed["directories"]) == [row["path"] for row in bindings["directories"]],
                 "CANDIDATE_CHANGED", "STALE")
        forbidden = receipt_ids | {proposal_pin[:2], review_pin[:2], policy[0][:2]}
        _require(not any(pin[:2] in forbidden for pin in observed["files"].values()), "INPUT_INVALID")
        _require(all(pin[6] == expected[name]["bytes"] for name, pin in observed["files"].items()),
                 "CANDIDATE_CHANGED", "STALE")
        screen_pins = None
        if screen is not None:
            phase = "screen_controls"
            forbidden |= {pin[:2] for pin in observed["files"].values()}
            scanner_raw, scanner_pin = gate._read_control(scanner_path, 65536, trusted_code=True,
                                                         forbidden_ids=forbidden)
            terms_raw, terms_pin = gate._read_control(private_terms_path, 65536,
                                                     forbidden_ids=forbidden | {scanner_pin[:2]})
            _terms_valid(terms_raw)
            _require(gate._sha(scanner_raw) == gate.SCANNER_SHA256 == screen["scanner_sha256"]
                     and gate._sha(terms_raw) == screen["private_terms_sha256"], "CONTROL_CHANGED", "STALE")
            screen_pins = {"scanner": (scanner_pin, gate._sha(scanner_raw)),
                           "terms": (terms_pin, gate._sha(terms_raw))}
        phase = "candidate"
        root_fd = gate._open_dir(candidate)
        _require(gate._identity(os.fstat(root_fd)) == observed["directories"][""], "CANDIDATE_CHANGED", "STALE")
        captured = {}
        for name, row in expected.items():
            summary["content_reads"] += 1
            raw = gate._read_member(root_fd, name, observed["files"][name], gate.MAX_FILE)
            _require(len(raw) == row["bytes"] and gate._sha(raw) == row["sha256"], "CANDIDATE_CHANGED", "STALE")
            _require("\x00" not in raw.decode("utf-8"), "CANDIDATE_CHANGED", "STALE")
            captured[name] = raw
        _require(gate._inventory(candidate) == observed
                 and gate._identity(os.fstat(root_fd)) == observed["directories"][""], "CANDIDATE_CHANGED", "STALE")
        phase = "controls"
        gate._recheck_inputs(proposal_path, review_path, pins)
        if screen_pins is not None:
            phase = "screen_controls"
            for path, key in ((scanner_path, "scanner"), (private_terms_path, "terms")):
                raw, pin = gate._read_control(path, 65536, trusted_code=key == "scanner",
                                              expected_pin=screen_pins[key][0], forbidden_ids=forbidden)
                _require((pin, gate._sha(raw)) == screen_pins[key], "CONTROL_CHANGED", "STALE")
        phase = "controls"
        _require(gate._policy_snapshot(expected_pin=policy[0]) == policy, "POLICY_CHANGED", "STALE")
        _require(gate._bindings(proposal, observed, captured, pins, policy, screen_pins) == bindings,
                 "INPUT_CHANGED", "STALE")
        phase = "receipt_recheck"
        _require(_receipt_snapshot(receipt) == evidence, "RECEIPT_CHANGED", "STALE")
        phase = "candidate"
        _require(gate._inventory(candidate) == observed
                 and gate._identity(os.fstat(root_fd)) == observed["directories"][""],
                 "CANDIDATE_CHANGED", "STALE")
        summary["status"] = "MATCHED"
    except VerificationIssue as error:
        if phase == "receipt_recheck":
            summary["status"], summary["reason_codes"] = "STALE", ["RECEIPT_CHANGED"]
        else:
            summary["status"], summary["reason_codes"] = error.status, [error.code]
    except gate.GateIssue as error:
        if phase in {"receipt", "receipt_recheck"}:
            summary["status"] = "STALE" if phase == "receipt_recheck" else "REFUSED"
            summary["reason_codes"] = ["RECEIPT_CHANGED" if phase == "receipt_recheck" else "RECEIPT_INVALID"]
        elif error.eligibility == "HOLD" or phase == "candidate":
            summary["status"], summary["reason_codes"] = "STALE", ["CANDIDATE_CHANGED" if phase == "candidate" else "INPUT_CHANGED"]
        else:
            summary["reason_codes"] = ["INPUT_INVALID"]
    except OSError as error:
        if phase == "receipt_recheck":
            summary["status"], summary["reason_codes"] = "STALE", ["RECEIPT_CHANGED"]
        elif error.errno == errno.ENOENT:
            summary["status"], summary["reason_codes"] = "UNVERIFIABLE", ["RECEIPT_INCOMPLETE" if phase == "receipt" else "INPUT_UNAVAILABLE"]
        elif phase == "candidate":
            summary["status"], summary["reason_codes"] = "STALE", ["CANDIDATE_CHANGED"]
        else:
            summary["reason_codes"] = ["RECEIPT_INVALID" if phase == "receipt" else "INPUT_INVALID"]
    except (ValueError, TypeError, OverflowError, RecursionError):
        if phase == "receipt_recheck":
            summary["status"], summary["reason_codes"] = "STALE", ["RECEIPT_CHANGED"]
        else:
            summary["reason_codes"] = ["RECEIPT_INVALID" if phase == "receipt" else "INPUT_INVALID"]
    except Exception:
        summary["reason_codes"] = ["INTERNAL_REFUSAL"]
    finally:
        if root_fd is not None:
            try:
                os.close(root_fd)
            except OSError:
                summary["status"], summary["reason_codes"] = "REFUSED", ["INPUT_UNAVAILABLE"]
    return summary


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise VerificationIssue("REFUSED", "CLI_ARGUMENTS")


def main(argv=None):
    summary = _summary()
    try:
        parser = _Parser(prog="verify-source-export-receipt", allow_abbrev=False, description=__doc__)
        for name in ("candidate", "proposal", "review", "receipt"):
            parser.add_argument("--" + name, required=True)
        parser.add_argument("--scanner")
        parser.add_argument("--private-terms")
        args = parser.parse_args(argv)
        summary = verify(args.candidate, args.proposal, args.review, args.receipt,
                         scanner_path=args.scanner, private_terms_path=args.private_terms)
    except VerificationIssue as error:
        summary["reason_codes"] = [error.code]
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0 if summary["status"] == "MATCHED" else 2 if summary["status"] == "REFUSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
