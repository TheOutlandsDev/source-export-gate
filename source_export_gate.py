"""Local, private artifact eligibility before a pinned offline text screen.

No candidate copying, Git operation, network, publication or hold recovery.
Review declarations are supplied owner assertions, not authenticated provenance.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


FAMILIES = {
    "code-atlas": "Code Atlas",
    "java-python-kits": "Java/Python utilities and server kits",
    "coding-agent-methods": "Coding Agent and local-Codex methods",
    "agent-workbench": "Agent Workbench",
    "wow-rebuild": "WoW and rebuild kits",
    "game-tools-ott": "Game Tools and OTT kit",
    "workflow-lab": "Workflow Lab",
    "blueprint-methods": "Reusable blueprint/catalog methods",
}
MAX_META = 262144
MAX_FILES = 128
MAX_FILE = 2000000
MAX_TOTAL = 8000000
MAX_ENTRIES = 512
MAX_DEPTH = 8
SCANNER_SHA256 = "f1c70a7edae1ccad69e78fa18c03d708eabdf4f72e3b20f11add585551d53ff5"
POLICY_ID = "outlands-source-export-policy-v02"
CLAIM_RAW = b'{"format":"outlands-source-export-claim-v2","publication_authorized":false,"export_performed":false}\n'
ELIGIBLE_KINDS = {"source", "documentation", "synthetic_example", "notice"}
OTHER_KINDS = {
    "log", "runtime_record", "configuration", "credential", "database",
    "backup", "archive", "patch", "git_metadata", "model_data",
    "employer_material", "client_material", "unknown",
}
DENIED_COMPONENTS = {
    ".git", ".hg", ".svn", ".github", ".gitlab", ".secrets", "secrets", "secret",
    ".ssh", ".aws", ".kube", ".docker", ".config", ".vscode",
    "credentials", "credential", "logs", "log", "runtime", "data", "backups", "backup",
    "exports", "export", "bundles", "runs", "run", "__pycache__",
    "node_modules", ".cache", "cache", "models", "weights", "receipts",
}
DENIED_SUFFIXES = {
    ".log", ".diff", ".patch", ".env", ".db", ".sqlite", ".sqlite3", ".sqlitedb",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar",
    ".key", ".pem", ".p12", ".pfx", ".crt", ".cer", ".kdbx",
    ".jar", ".class", ".pyc", ".pyo", ".vsix", ".exe", ".dll", ".so",
    ".bin", ".png", ".jpg", ".jpeg", ".pdf", ".docx", ".xlsx",
    ".jsonl", ".ndjson", ".gguf", ".safetensors", ".pt", ".pth", ".onnx", ".ckpt",
}
DENIED_NAMES = {
    "runtime.json", "run.json", "result.json", "events.jsonl", "history.json",
    "credentials.json", "secrets.json", "config.json", "compose.yaml",
    "compose.yml", "docker-compose.yml", "docker-compose.yaml", ".gitconfig",
    ".gitmodules", ".gitattributes", ".netrc", ".npmrc", ".pypirc",
    "id_rsa", "id_ed25519", "known_hosts", "authorized_keys",
    "server-info.json", "hold.json", "state.json", "session.json", "attempt.json", "job.json", ".ds_store",
}
REVIEW_STATES = {"reviewed", "unknown", "pending", "hold", "excluded"}
DECISIONS = {"eligible", "unknown", "pending", "hold", "excluded"}
NOTICE_STATES = {"preserved", "unknown", "pending", "hold", "excluded"}
SEGMENT = re.compile(r"[A-Za-z0-9._-]+\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


class GateIssue(Exception):
    def __init__(self, code, eligibility="REFUSED", scanner_called=False):
        super().__init__(code)
        self.code = code
        self.eligibility = eligibility
        self.scanner_called = scanner_called


def _need(condition, code, eligibility="REFUSED"):
    if not condition:
        raise GateIssue(code, eligibility)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _absolute(value):
    raw = os.fspath(value)
    _need(type(raw) is str and 0 < len(raw) <= 4096 and "\x00" not in raw
          and not raw.startswith("//"), "ABSOLUTE_PATH")
    path = Path(raw)
    _need(path.is_absolute() and ".." not in path.parts, "ABSOLUTE_PATH")
    return path


def _inside(path, root):
    return path == root or root in path.parents


def _open_dir(path):
    path = _absolute(path)
    fd = os.open("/", DIR_FLAGS)
    try:
        for name in path.parts[1:]:
            child = os.open(name, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _private_dir(fd):
    info = os.fstat(fd)
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
          and stat.S_IMODE(info.st_mode) == 0o700, "PRIVATE_DIRECTORY")
    return info


def _read_at(parent, name, maximum, modes, *, expected_pin=None, forbidden_ids=()):
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    _need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
          and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) in modes
          and before.st_size <= maximum, "PRIVATE_FILE")
    _need(expected_pin is None or _identity(before) == expected_pin, "INPUT_CHANGED", "HOLD")
    _need(_identity(before)[:2] not in forbidden_ids, "CONTROL_ALIAS")
    fd = os.open(name, FILE_FLAGS, dir_fd=parent)
    try:
        _need(_identity(before) == _identity(os.fstat(fd)), "INPUT_CHANGED", "HOLD")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        _need(len(data) == before.st_size and len(data) <= maximum
              and _identity(before) == _identity(after) == _identity(named),
              "INPUT_CHANGED", "HOLD")
        return bytes(data), _identity(after)
    finally:
        os.close(fd)


def _read_control(path, maximum=MAX_META, trusted_code=False, *, expected_pin=None, forbidden_ids=()):
    path = _absolute(path)
    parent = _open_dir(path.parent)
    try:
        if not trusted_code:
            _private_dir(parent)
        return _read_at(parent, path.name, maximum, {0o600, 0o644} if trusted_code else {0o600},
                        expected_pin=expected_pin, forbidden_ids=forbidden_ids)
    finally:
        os.close(parent)


def _parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result, "JSON_DUPLICATE")
            result[key] = value
        return result

    def constant(_value):
        raise GateIssue("JSON_NONFINITE")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise GateIssue("JSON_INVALID") from None


def _exact(value, fields):
    return type(value) is dict and set(value) == set(fields)


def _relative(value):
    _need(type(value) is str and 1 <= len(value) <= 240, "PATH_SCHEMA")
    parts = value.split("/")
    _need(len(parts) <= MAX_DEPTH and all(
        part not in {"", ".", ".."} and SEGMENT.fullmatch(part) for part in parts),
        "PATH_SCHEMA")
    return parts


def _path_eligible(name):
    parts = _relative(name)
    lower = [part.casefold() for part in parts]
    leaf = lower[-1]
    suffixes = Path(leaf).suffixes
    return (not any(part in DENIED_COMPONENTS for part in lower)
            and not leaf.startswith(".env") and leaf not in DENIED_NAMES
            and ".env" not in suffixes and not leaf.startswith(".sqlite")
            and not any(suffix.startswith(".sqlite") for suffix in suffixes)
            and Path(leaf).suffix not in DENIED_SUFFIXES)


def _proposal(doc):
    _need(_exact(doc, {"format", "family", "files"})
          and doc["format"] == "outlands-source-export-proposal-v1"
          and type(doc["family"]) is str and doc["family"] in FAMILIES
          and type(doc["files"]) is list and 1 <= len(doc["files"]) <= MAX_FILES,
          "PROPOSAL_SCHEMA")
    names, total = [], 0
    for row in doc["files"]:
        _need(_exact(row, {"path", "sha256", "bytes", "artifact_kind", "synthetic_fixture"}), "PROPOSAL_SCHEMA")
        _relative(row["path"])
        _need(type(row["sha256"]) is str and DIGEST.fullmatch(row["sha256"])
              and type(row["bytes"]) is int and 0 <= row["bytes"] <= MAX_FILE
              and type(row["artifact_kind"]) is str
              and row["artifact_kind"] in ELIGIBLE_KINDS | OTHER_KINDS
              and type(row["synthetic_fixture"]) is bool, "PROPOSAL_SCHEMA")
        names.append(row["path"])
        total += row["bytes"]
    _need(names == sorted(set(names)) and total <= MAX_TOTAL, "PROPOSAL_LIMIT_OR_ORDER")


def _review(doc):
    _need(_exact(doc, {"format", "family", "proposal_sha256", "publication_authorized", "files"})
          and doc["format"] == "outlands-source-export-review-v1"
          and type(doc["family"]) is str and doc["family"] in FAMILIES
          and type(doc["proposal_sha256"]) is str and DIGEST.fullmatch(doc["proposal_sha256"])
          and doc["publication_authorized"] is False and type(doc["files"]) is list
          and 1 <= len(doc["files"]) <= MAX_FILES, "REVIEW_SCHEMA")
    names = []
    for row in doc["files"]:
        _need(_exact(row, {"path", "sha256", "artifact_kind", "decision", "source_authority",
                          "ownership", "confidentiality", "rights", "notices"}), "REVIEW_SCHEMA")
        _relative(row["path"])
        _need(type(row["sha256"]) is str and DIGEST.fullmatch(row["sha256"])
              and type(row["artifact_kind"]) is str and row["artifact_kind"] in ELIGIBLE_KINDS | OTHER_KINDS
              and type(row["decision"]) is str and row["decision"] in DECISIONS
              and type(row["notices"]) is str and row["notices"] in NOTICE_STATES
              and all(type(row[key]) is str and row[key] in REVIEW_STATES for key in
                      ("source_authority", "ownership", "confidentiality", "rights")), "REVIEW_SCHEMA")
        names.append(row["path"])
    _need(names == sorted(set(names)), "REVIEW_ORDER")


def _eligible(proposal, review, proposal_sha):
    _need(proposal["family"] == review["family"] and review["proposal_sha256"] == proposal_sha,
          "REVIEW_BINDING", "HOLD")
    _need([x["path"] for x in proposal["files"]] == [x["path"] for x in review["files"]],
          "REVIEW_SET", "HOLD")
    for item, assertion in zip(proposal["files"], review["files"]):
        _need(item["sha256"] == assertion["sha256"] and item["artifact_kind"] == assertion["artifact_kind"],
              "REVIEW_BINDING", "HOLD")
        _need(item["artifact_kind"] in ELIGIBLE_KINDS and _path_eligible(item["path"]),
              "ARTIFACT_INELIGIBLE", "HOLD")
        _need(item["artifact_kind"] != "synthetic_example" or item["synthetic_fixture"] is True,
              "SYNTHETIC_DECLARATION", "HOLD")
        _need(assertion["decision"] == "eligible" and assertion["notices"] == "preserved"
              and all(assertion[key] == "reviewed" for key in
                      ("source_authority", "ownership", "confidentiality", "rights")),
              "REVIEW_INCOMPLETE", "HOLD")


def _inventory(candidate_root):
    root_fd = None
    files, directories, visited, total = {}, {}, 0, 0
    try:
        root_fd = _open_dir(candidate_root)
        def walk(fd, prefix, depth):
            nonlocal visited, total
            before = _private_dir(fd)
            directories[prefix] = _identity(before)
            with os.scandir(fd) as entries:
                for entry in entries:
                    visited += 1
                    _need(visited <= MAX_ENTRIES, "CANDIDATE_LIMIT", "HOLD")
                    name = prefix + "/" + entry.name if prefix else entry.name
                    _relative(name)
                    info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                    _need(info.st_uid == os.getuid(), "CANDIDATE_UNSAFE", "HOLD")
                    if stat.S_ISDIR(info.st_mode):
                        _need(depth < MAX_DEPTH and stat.S_IMODE(info.st_mode) == 0o700,
                              "CANDIDATE_UNSAFE", "HOLD")
                        child = os.open(entry.name, DIR_FLAGS, dir_fd=fd)
                        try:
                            _need(_identity(info) == _identity(os.fstat(child)), "CANDIDATE_CHANGED", "HOLD")
                            walk(child, name, depth + 1)
                            _need(_identity(info) == _identity(os.stat(entry.name, dir_fd=fd, follow_symlinks=False)),
                                  "CANDIDATE_CHANGED", "HOLD")
                        finally:
                            os.close(child)
                    else:
                        _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                              and stat.S_IMODE(info.st_mode) == 0o600, "CANDIDATE_UNSAFE", "HOLD")
                        total += info.st_size
                        _need(len(files) < MAX_FILES and info.st_size <= MAX_FILE and total <= MAX_TOTAL,
                              "CANDIDATE_LIMIT", "HOLD")
                        files[name] = _identity(info)
            _need(_identity(before) == _identity(os.fstat(fd)), "CANDIDATE_CHANGED", "HOLD")
        walk(root_fd, "", 0)
        return {"directories": directories, "files": files}
    except GateIssue as error:
        raise GateIssue(error.code, "HOLD") from None
    except OSError:
        raise GateIssue("CANDIDATE_UNSAFE", "HOLD") from None
    finally:
        if root_fd is not None:
            os.close(root_fd)


def _read_member(root_fd, relative, expected_pin, maximum):
    parent = os.dup(root_fd)
    try:
        parts = _relative(relative)
        for name in parts[:-1]:
            child = os.open(name, DIR_FLAGS, dir_fd=parent)
            os.close(parent)
            parent = child
            _private_dir(parent)
        raw, pin = _read_at(parent, parts[-1], maximum, {0o600}, expected_pin=expected_pin)
        _need(pin == expected_pin, "CANDIDATE_CHANGED", "HOLD")
        return raw
    except GateIssue as error:
        raise GateIssue(error.code, "HOLD") from None
    except OSError:
        raise GateIssue("CANDIDATE_CHANGED", "HOLD") from None
    finally:
        os.close(parent)


def _recheck_inputs(proposal_path, review_path, input_pins):
    for path, expected in zip((proposal_path, review_path), input_pins):
        raw, pin = _read_control(path, expected_pin=expected[0])
        _need((pin, _sha(raw)) == expected, "INPUT_CHANGED", "HOLD")


def _screen_snapshot(scanner_path, private_terms_path, proposal, captured, *, forbidden_ids=()):
    scanner_raw, scanner_pin = _read_control(scanner_path, 65536, trusted_code=True,
                                           forbidden_ids=forbidden_ids)
    _need(_sha(scanner_raw) == SCANNER_SHA256, "SCANNER_PIN")
    terms_raw, terms_pin = _read_control(private_terms_path, 65536,
                                       forbidden_ids=set(forbidden_ids) | {scanner_pin[:2]})
    _need(scanner_pin[:2] != terms_pin[:2], "CONTROL_ALIAS")
    terms = _parse(terms_raw)
    _need(_exact(terms, {"schema_version", "terms"}) and type(terms["schema_version"]) is int
          and terms["schema_version"] == 1 and type(terms["terms"]) is list
          and 1 <= len(terms["terms"]) <= 64, "TERMS_SCHEMA")
    _need(all(type(term) is str and 4 <= len(term) <= 128 and all(ord(c) >= 32 for c in term)
              for term in terms["terms"])
          and len({term.casefold() for term in terms["terms"]}) == len(terms["terms"]), "TERMS_SCHEMA")
    namespace = {"__name__": "outlands_pinned_offline_screen", "__file__": "<pinned-offline-screen>"}
    evaluated = False
    try:
        exec(compile(scanner_raw, "<pinned-offline-screen>", "exec"), namespace)
        manifest = {"base_commit": "0" * 40, "files": [
            {"path": row["path"], "sha256": row["sha256"], "synthetic_fixture": row["synthetic_fixture"]}
            for row in proposal["files"]]}
        base = {"base_commit": "0" * 40, "paths": sorted(captured)}
        evaluated = True
        rows, findings = namespace["evaluate"](manifest, base, dict(captured), [x.casefold() for x in terms["terms"]])
        _need(type(rows) is list and len(rows) == len(captured) and type(findings) is list
              and len(findings) <= MAX_FILES * 32, "SCANNER_SHAPE")
        for finding in findings:
            _need(_exact(finding, {"path", "check"}) and type(finding["path"]) is str
                  and finding["path"] in captured and type(finding["check"]) is str
                  and CODE.fullmatch(finding["check"]), "SCANNER_SHAPE")
        return {"findings": findings, "control_pins": {
            "scanner": (scanner_pin, _sha(scanner_raw)), "terms": (terms_pin, _sha(terms_raw))}}
    except Exception:
        raise GateIssue("SCANNER_ERROR", scanner_called=evaluated) from None


def _result():
    return {"format": "outlands-source-export-result-v2", "eligibility": "REFUSED",
            "reason_codes": [], "family": None, "proposed_files": 0, "observed_files": 0,
            "content_reads": 0, "scanner_called": False, "text_review": "NOT_RUN", "findings": [],
            "publication_status": "HELD", "publication_authorized": False,
            "export_performed": False, "destination_verified": False, "git_metadata_reviewed": False,
            "bindings": None}


def _policy_snapshot(*, expected_pin=None):
    """Pin installed engine bytes, not an authenticated running interpreter image."""
    raw, pin = _read_control(_absolute(__file__), MAX_META, trusted_code=True,
                             expected_pin=expected_pin)
    return pin, _sha(raw)


def _bindings(proposal, observed, captured, input_pins, policy_pin, screen_pins):
    """Bind only already captured buffers, never reopen candidate paths for pins."""
    return {"format": "outlands-source-export-bindings-v1",
            "policy": {"id": POLICY_ID, "engine_sha256": policy_pin[1]},
            "proposal_sha256": input_pins[0][1], "review_sha256": input_pins[1][1],
            "files": [{"path": row["path"], "sha256": _sha(captured[row["path"]]),
                       "bytes": len(captured[row["path"]]), "mode": "0600",
                       "artifact_kind": row["artifact_kind"],
                       "synthetic_fixture": row["synthetic_fixture"]}
                      for row in proposal["files"]],
            "directories": [{"path": path, "mode": "0700"}
                            for path in sorted(observed["directories"])],
            "screen": None if screen_pins is None else {
                "scanner_sha256": screen_pins["scanner"][1],
                "private_terms_sha256": screen_pins["terms"][1]}}


def assess(candidate_root, proposal_path, review_path, *, scanner_path=None, private_terms_path=None):
    """Assess only explicit private candidate bytes; never exports or authorizes."""
    result = _result()
    root_fd = None
    phase = "controls"
    try:
        candidate = _absolute(candidate_root)
        proposal_path, review_path = _absolute(proposal_path), _absolute(review_path)
        _need((scanner_path is None) == (private_terms_path is None), "SCANNER_ARGUMENTS")
        controls = [proposal_path, review_path]
        if scanner_path is not None:
            scanner_path, private_terms_path = _absolute(scanner_path), _absolute(private_terms_path)
            controls += [scanner_path, private_terms_path]
        _need(len(set(controls)) == len(controls) and not any(_inside(p, candidate) for p in controls), "CONTROL_LOCATION")
        policy_path = _absolute(__file__)
        _need(not _inside(policy_path, candidate) and policy_path not in controls, "POLICY_LOCATION")
        policy_pin = _policy_snapshot()
        proposal_raw, proposal_pin = _read_control(proposal_path, forbidden_ids={policy_pin[0][:2]})
        review_raw, review_pin = _read_control(review_path, forbidden_ids={policy_pin[0][:2], proposal_pin[:2]})
        _need(proposal_pin[:2] != review_pin[:2], "CONTROL_ALIAS")
        proposal, review = _parse(proposal_raw), _parse(review_raw)
        _proposal(proposal)
        result["family"], result["proposed_files"] = proposal["family"], len(proposal["files"])
        _review(review)
        _eligible(proposal, review, _sha(proposal_raw))
        phase = "candidate"
        observed = _inventory(candidate)
        result["observed_files"] = len(observed["files"])
        expected = {row["path"]: row for row in proposal["files"]}
        dirs = {""}
        for path in expected:
            parts = path.split("/")
            dirs.update("/".join(parts[:i]) for i in range(1, len(parts)))
        _need(set(observed["files"]) == set(expected) and set(observed["directories"]) == dirs,
              "CANDIDATE_SET", "HOLD")
        _need(not any(pin[:2] in {proposal_pin[:2], review_pin[:2], policy_pin[0][:2]} for pin in observed["files"].values()),
              "CONTROL_ALIAS", "HOLD")
        _need(all(pin[6] == expected[name]["bytes"] for name, pin in observed["files"].items()),
              "SIZE_CHANGED", "HOLD")
        root_fd = _open_dir(candidate)
        _need(_identity(os.fstat(root_fd)) == observed["directories"][""], "CANDIDATE_CHANGED", "HOLD")
        captured = {}
        for name, row in expected.items():
            result["content_reads"] += 1
            raw = _read_member(root_fd, name, observed["files"][name], MAX_FILE)
            _need(len(raw) == row["bytes"] and _sha(raw) == row["sha256"], "HASH_CHANGED", "HOLD")
            try:
                text = raw.decode("utf-8")
            except UnicodeError:
                raise GateIssue("TEXT_ONLY", "HOLD") from None
            _need("\x00" not in text, "TEXT_ONLY", "HOLD")
            captured[name] = raw
        _need(_inventory(candidate) == observed, "CANDIDATE_CHANGED", "HOLD")
        _need(_identity(os.fstat(root_fd)) == observed["directories"][""], "CANDIDATE_CHANGED", "HOLD")
        pins = ((proposal_pin, _sha(proposal_raw)), (review_pin, _sha(review_raw)))
        _recheck_inputs(proposal_path, review_path, pins)
        screen_pins = None
        if scanner_path is not None:
            phase = "scanner"
            forbidden_ids = {pin[:2] for pin in observed["files"].values()} | {proposal_pin[:2], review_pin[:2], policy_pin[0][:2]}
            screened = _screen_snapshot(scanner_path, private_terms_path, proposal, captured,
                                        forbidden_ids=forbidden_ids)
            result["scanner_called"] = True
            result["findings"] = screened["findings"]
            result["text_review"] = "REVIEW" if result["findings"] else "PASS"
            phase = "candidate"
            _need(_inventory(candidate) == observed, "CANDIDATE_CHANGED", "HOLD")
            _recheck_inputs(proposal_path, review_path, pins)
            for path, key in ((scanner_path, "scanner"), (private_terms_path, "terms")):
                if key in screened["control_pins"]:
                    raw, pin = _read_control(path, 65536, trusted_code=key == "scanner",
                                             expected_pin=screened["control_pins"][key][0],
                                             forbidden_ids=forbidden_ids)
                    _need((pin, _sha(raw)) == screened["control_pins"][key], "CONTROL_CHANGED", "HOLD")
            screen_pins = screened["control_pins"]
        _need(_policy_snapshot(expected_pin=policy_pin[0]) == policy_pin, "POLICY_CHANGED", "HOLD")
        phase = "candidate"
        _need(_inventory(candidate) == observed
              and _identity(os.fstat(root_fd)) == observed["directories"][""], "CANDIDATE_CHANGED", "HOLD")
        result["bindings"] = _bindings(proposal, observed, captured, pins, policy_pin, screen_pins)
        result["eligibility"] = "ELIGIBLE_FOR_TEXT_REVIEW"
    except GateIssue as error:
        result["eligibility"] = error.eligibility
        result["reason_codes"] = [error.code]
        result["scanner_called"] = result["scanner_called"] or error.scanner_called
    except OSError:
        result["eligibility"] = "HOLD" if phase == "candidate" else "REFUSED"
        result["reason_codes"] = ["INPUT_UNAVAILABLE"]
    except (ValueError, TypeError, OverflowError, RecursionError):
        result["reason_codes"] = ["INPUT_UNAVAILABLE"]
    except Exception:
        result["reason_codes"] = ["INTERNAL_REFUSAL"]
    finally:
        if root_fd is not None:
            os.close(root_fd)
    return result


def _summary(result):
    value = {key: item for key, item in result.items() if key not in {"findings", "bindings"}}
    value["format"] = "outlands-source-export-cli-v2"
    value["finding_count"] = len(result["findings"])
    return value


def _create_receipt(path, candidate, controls):
    path, candidate = _absolute(path), _absolute(candidate)
    _need(not _inside(path, candidate) and not _inside(candidate, path)
          and not any(_inside(_absolute(p), path) for p in controls), "RECEIPT_LOCATION")
    parent = _open_dir(path.parent)
    try:
        _private_dir(parent)
        os.mkdir(path.name, 0o700, dir_fd=parent)
        fd = os.open(path.name, DIR_FLAGS, dir_fd=parent)
        try:
            _private_dir(fd)
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent)


def _write_new(fd, name, raw):
    out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    with os.fdopen(out, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def _write_result(fd, result):
    body = ("# Private local Source Export Gate receipt\n\n"
            + "Recorded UTC: " + datetime.now(timezone.utc).isoformat() + "\n\n"
            + "Eligibility: " + result["eligibility"] + ". Text review: " + result["text_review"] + ".\n\n"
            + "Publication: HELD. Authorization: false. Export performed: false.\n\n"
            + "Supplied owner review assertions are not authenticated authorship, confidentiality, rights or provenance proof. "
            + "A zero exit is a bounded local check only. The text screen is incomplete; unknown confidentiality stays held. "
            + "No Git history, remote ownership/access, live provider, inference, real-source family or original Java hold is checked. "
            + "No source copy, upload, repository/access/license/service action is performed. "
            + "Input bindings describe the exact captured buffers only when assessment completed. "
            + "The read-only verifier checks freshness without rerunning the text screen. "
            + "Unsigned hashes do not authenticate this receipt or prevent coherent owner rewriting. "
            + "Require the complete five-file receipt; partial/write-failed evidence is unqualified. "
            + "Sequential pinned reads assume trusted stable single-owner storage, not an atomic multiwriter filesystem.\n")
    artifact_hashes = {"CLAIM.json": _sha(CLAIM_RAW)}
    for name in ("REVIEW.md", "REVIEW.txt"):
        raw = body.encode()
        _write_new(fd, name, raw)
        artifact_hashes[name] = _sha(raw)
    raw = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
    _write_new(fd, "result.json", raw)
    artifact_hashes["result.json"] = _sha(raw)
    complete = {"format": "outlands-source-export-complete-v1", "files": artifact_hashes}
    _write_new(fd, "COMPLETE.json", (json.dumps(complete, indent=2, sort_keys=True) + "\n").encode())


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise GateIssue("CLI_ARGUMENTS")


def main(argv=None):
    os.umask(0o077)
    result, receipt_fd = _result(), None
    try:
        parser = _Parser(prog="source-export-gate", allow_abbrev=False, description=__doc__)
        for name in ("candidate", "proposal", "review", "receipt"):
            parser.add_argument("--" + name, required=True)
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--eligibility-only", action="store_true")
        group.add_argument("--scanner")
        parser.add_argument("--private-terms")
        args = parser.parse_args(argv)
        _need(bool(args.scanner) == bool(args.private_terms), "CLI_ARGUMENTS")
        controls = [args.proposal, args.review]
        if args.scanner:
            controls += [args.scanner, args.private_terms]
        receipt_fd = _create_receipt(args.receipt, args.candidate, controls)
        _write_new(receipt_fd, "CLAIM.json", CLAIM_RAW)
        result = assess(args.candidate, args.proposal, args.review,
                        scanner_path=args.scanner, private_terms_path=args.private_terms)
        _write_result(receipt_fd, result)
    except GateIssue as error:
        result["eligibility"], result["reason_codes"] = "REFUSED", [error.code]
        result["bindings"] = None
    except (OSError, ValueError, TypeError):
        result["eligibility"], result["reason_codes"] = "REFUSED", ["RECEIPT_UNAVAILABLE"]
        result["bindings"] = None
    except Exception:
        result["eligibility"], result["reason_codes"] = "REFUSED", ["INTERNAL_REFUSAL"]
        result["bindings"] = None
    finally:
        if receipt_fd is not None:
            os.close(receipt_fd)
    print(json.dumps(_summary(result), sort_keys=True, separators=(",", ":")))
    if result["eligibility"] == "REFUSED":
        return 2
    return 1 if result["eligibility"] == "HOLD" or result["text_review"] == "REVIEW" else 0


if __name__ == "__main__":
    raise SystemExit(main())
