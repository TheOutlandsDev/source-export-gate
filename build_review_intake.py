"""Create a private pending review intake from explicit selected text only.

Declarations and hashes confer no source authority, confidentiality or approval.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat


_spec = importlib.util.spec_from_file_location(
    "outlands_intake_gate", Path(__file__).absolute().with_name("source_export_gate.py"))
gate = importlib.util.module_from_spec(_spec)
exec(compile(_spec.loader.get_source(_spec.name), _spec.origin, "exec"), gate.__dict__)

OUTPUT_FILES = ("CLAIM.json", "proposal.json", "review-draft.json", "CHECKLIST.md",
                "CHECKLIST.txt", "INTAKE-COMPLETE.json")
PENDING_FIELDS = ("decision", "source_authority", "ownership", "confidentiality", "rights", "notices")
ERROR_CODES = {"REVIEW_PENDING", "SELECTION_SCHEMA", "ARTIFACT_INELIGIBLE", "CONTROL_LOCATION",
               "OUTPUT_EXISTS", "OUTPUT_UNAVAILABLE", "INPUT_UNSAFE", "INPUT_LIMIT", "TEXT_ONLY",
               "INPUT_CHANGED", "POLICY_CHANGED", "INTERNAL_REFUSAL", "CLI_ARGUMENTS"}
CLAIM_RAW = b'{"format":"outlands-source-export-intake-claim-v1","status":"HOLD","publication_authorized":false,"export_performed":false}\n'
CHECKLIST_RAW = (
    "# Pending private source review\n\n"
    "Status: HOLD. Every file's decision, source_authority, ownership, confidentiality, rights "
    "and notices fields are pending. No review or approval has been completed.\n\n"
    "The proposal records only explicitly selected paths, byte sizes, hashes and supplied "
    "artifact declarations. A declared kind or synthetic flag does not establish eligibility, "
    "invented data, source authority, authorship, confidentiality or redistribution rights. "
    "Review each selected file and resolve every pending field independently. Preserve "
    "required notices; do not mark unresolved questions reviewed or notices preserved.\n\n"
    "The pending draft must remain HOLD/REVIEW_INCOMPLETE under the source gate. This intake "
    "does not run an assessor or text screen, copy source payloads, inspect unselected content, "
    "review Git metadata, verify a destination or authorize export/publication. Publication "
    "remains HELD and all authority/export flags remain false.\n\n"
    "Completion identifies these pending metadata buffers only. It is not producer-exit, "
    "authenticated-review, crash-durability or atomic-multiwriter proof. Trusted stable "
    "owner storage is assumed. Preserve partial writes and caller uncertainty; do not "
    "repair, adopt, clean up or automatically retry them.\n"
).encode("utf-8")


class IntakeIssue(Exception):
    def __init__(self, code):
        self.code = code if type(code) is str and code in ERROR_CODES else "INTERNAL_REFUSAL"
        super().__init__(self.code)


def _need(condition, code="INPUT_UNSAFE"):
    if not condition:
        raise IntakeIssue(code)


def _result():
    return {"format": "outlands-private-review-intake-result-v1", "status": "REFUSED",
            "reason_codes": [], "declared_files": 0, "content_reads": 0, "recheck_reads": 0, "draft_created": False,
            "complete_written": False, "files_written": [], "publication_status": "HELD",
            "publication_authorized": False, "export_performed": False, "destination_verified": False,
            "git_metadata_reviewed": False, "scanner_called": False, "bindings": None}


def _selection(value):
    _need(gate._exact(value, {"format", "family", "files"})
          and value["format"] == "outlands-source-export-intake-selection-v1"
          and type(value["family"]) is str and value["family"] in gate.FAMILIES
          and type(value["files"]) is list and 1 <= len(value["files"]) <= gate.MAX_FILES,
          "SELECTION_SCHEMA")
    names = []
    for row in value["files"]:
        _need(gate._exact(row, {"path", "artifact_kind", "synthetic_fixture"}), "SELECTION_SCHEMA")
        gate._relative(row["path"])
        _need(type(row["artifact_kind"]) is str and row["artifact_kind"] in gate.ELIGIBLE_KINDS | gate.OTHER_KINDS
              and type(row["synthetic_fixture"]) is bool, "SELECTION_SCHEMA")
        names.append(row["path"])
    _need(names == sorted(set(names)), "SELECTION_SCHEMA")
    for row in value["files"]:
        _need(row["artifact_kind"] in gate.ELIGIBLE_KINDS and gate._path_eligible(row["path"])
              and (row["artifact_kind"] != "synthetic_example" or row["synthetic_fixture"] is True), "ARTIFACT_INELIGIBLE")


def _policy_snapshot(expected=None):
    policies = {}
    for key, path in (("gate", gate._absolute(gate.__file__)), ("intake", gate._absolute(__file__))):
        raw, pin = gate._read_control(path, gate.MAX_META, trusted_code=True,
                                      expected_pin=None if expected is None else expected[key][0])
        policies[key] = (pin, gate._sha(raw))
    _need(len({value[0][:2] for value in policies.values()}) == 2, "CONTROL_LOCATION")
    return policies


def _locations(candidate, selection, output):
    code = (gate._absolute(gate.__file__), gate._absolute(__file__))
    _need(selection not in code and not gate._inside(selection, candidate)
          and not any(gate._inside(path, candidate) for path in code), "CONTROL_LOCATION")
    _need(not gate._inside(output, candidate) and not gate._inside(candidate, output)
          and not any(gate._inside(path, output) or gate._inside(output, path) for path in (selection, *code)), "CONTROL_LOCATION")


def _output_parent(output):
    fd = gate._open_dir(output.parent)
    try:
        pin = gate._identity(gate._private_dir(fd))
        try:
            os.stat(output.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return fd, pin
        raise IntakeIssue("OUTPUT_EXISTS")
    except BaseException:
        os.close(fd)
        raise


def _selected_metadata(context):
    root = context["root_fd"]
    root_pin = gate._identity(gate._private_dir(root))
    directories, files = {"": root_pin}, {}
    directory_ids, file_ids = {root_pin[:2]: ""}, set()
    forbidden = {context["selection_pin"][0][:2]} | {v[0][:2] for v in context["policies"].values()}
    for row in context["selection"]["files"]:
        parts = gate._relative(row["path"])
        parent, prefix = os.dup(root), ""
        try:
            for name in parts[:-1]:
                prefix = name if not prefix else prefix + "/" + name
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                _need(stat.S_ISDIR(before.st_mode) and before.st_uid == os.getuid()
                      and stat.S_IMODE(before.st_mode) == 0o700)
                child = os.open(name, gate.DIR_FLAGS, dir_fd=parent)
                try:
                    pin = gate._identity(gate._private_dir(child))
                    _need(pin == gate._identity(before), "INPUT_CHANGED")
                    _need(prefix not in directories or directories[prefix] == pin, "INPUT_CHANGED")
                    _need(pin[:2] not in directory_ids or directory_ids[pin[:2]] == prefix, "CONTROL_LOCATION")
                except BaseException:
                    os.close(child)
                    raise
                os.close(parent)
                parent = child
                directories[prefix], directory_ids[pin[:2]] = pin, prefix
            info = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                  and stat.S_IMODE(info.st_mode) == 0o600)
            _need(0 <= info.st_size <= gate.MAX_FILE, "INPUT_LIMIT")
            pin = gate._identity(info)
            _need(pin[:2] not in forbidden | file_ids, "CONTROL_LOCATION")
            file_ids.add(pin[:2])
            files[row["path"]] = pin
        finally:
            os.close(parent)
    _need(sum(pin[6] for pin in files.values()) <= gate.MAX_TOTAL, "INPUT_LIMIT")
    _need(context["parent_pin"][:2] not in directory_ids, "CONTROL_LOCATION")
    named = gate._open_dir(context["candidate"])
    try:
        _need(gate._identity(gate._private_dir(named)) == root_pin
              == gate._identity(os.fstat(root)), "INPUT_CHANGED")
    finally:
        os.close(named)
    return {"directories": directories, "files": files}


def _recheck(context):
    _need(_selected_metadata(context) == context["metadata"], "INPUT_CHANGED")
    for name, expected in context["captured"].items():
        context["result"]["recheck_reads"] += 1
        raw = gate._read_member(context["root_fd"], name, context["metadata"]["files"][name], gate.MAX_FILE)
        _need((len(raw), gate._sha(raw)) == expected, "INPUT_CHANGED")
    raw, pin = gate._read_control(context["selection_path"], expected_pin=context["selection_pin"][0])
    _need((pin, gate._sha(raw)) == context["selection_pin"], "INPUT_CHANGED")
    _need(_policy_snapshot(context["policies"]) == context["policies"], "POLICY_CHANGED")
    _need(_selected_metadata(context) == context["metadata"], "INPUT_CHANGED")


def _same_parent(context):
    named = gate._open_dir(context["output"].parent)
    try:
        current = gate._identity(gate._private_dir(context["parent_fd"]))
        _need(current[:5] == context["parent_pin"][:5]
              and current == gate._identity(gate._private_dir(named)), "OUTPUT_UNAVAILABLE")
    finally:
        os.close(named)


def _write_new(fd, name, raw):
    _need(type(raw) is bytes and len(raw) <= gate.MAX_META, "OUTPUT_UNAVAILABLE")
    out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        info = os.fstat(out)
        _need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
              and info.st_uid == os.getuid() and info.st_nlink == 1, "OUTPUT_UNAVAILABLE")
        with os.fdopen(out, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(out)


def _check_packet(context, fd, buffers):
    """Inspect only this newly created output, never candidate membership."""
    try:
        before = gate._identity(gate._private_dir(fd))
        names = set()
        with os.scandir(fd) as entries:
            for entry in entries:
                names.add(entry.name)
                _need(len(names) <= len(buffers), "OUTPUT_UNAVAILABLE")
        _need(names == set(buffers), "OUTPUT_UNAVAILABLE")
        pins = {}
        for name in sorted(names):
            raw, pins[name] = gate._read_at(fd, name, gate.MAX_META, {0o600})
            _need(raw == buffers[name] and gate._sha(raw) == gate._sha(buffers[name]), "OUTPUT_UNAVAILABLE")
        _need(len({pin[:2] for pin in pins.values()}) == len(buffers), "OUTPUT_UNAVAILABLE")
        _need(all(gate._identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == pin
                  for name, pin in pins.items()), "OUTPUT_UNAVAILABLE")
        _need(gate._identity(os.fstat(fd)) == before, "OUTPUT_UNAVAILABLE")
        named = gate._open_dir(context["output"])
        try:
            _need(gate._identity(gate._private_dir(named)) == before, "OUTPUT_UNAVAILABLE")
        finally:
            os.close(named)
    except IntakeIssue:
        raise
    except (gate.GateIssue, OSError, ValueError, TypeError):
        raise IntakeIssue("OUTPUT_UNAVAILABLE") from None


def _json_raw(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def build_intake(candidate_root, selection_path, output_path):
    result, context, packet, created, phase = _result(), {}, None, False, "arguments"
    try:
        candidate, selection_path, output = map(gate._absolute, (candidate_root, selection_path, output_path))
        _locations(candidate, selection_path, output)
        parent, parent_pin = _output_parent(output)
        context.update(parent_fd=parent, parent_pin=parent_pin, output=output, candidate=candidate,
                       selection_path=selection_path, result=result)
        phase = "selection"
        selection_raw, selection_pin = gate._read_control(selection_path)
        selection = gate._parse(selection_raw)
        _selection(selection)
        result["declared_files"] = len(selection["files"])
        policies = _policy_snapshot()
        _need(selection_pin[:2] not in {value[0][:2] for value in policies.values()}, "CONTROL_LOCATION")
        context.update(selection=selection, selection_pin=(selection_pin, gate._sha(selection_raw)), policies=policies)
        phase = "selected"
        context["root_fd"] = gate._open_dir(candidate)
        context["metadata"] = _selected_metadata(context)
        files, captured = [], {}
        for row in selection["files"]:
            result["content_reads"] += 1
            raw = gate._read_member(context["root_fd"], row["path"], context["metadata"]["files"][row["path"]], gate.MAX_FILE)
            try:
                text = raw.decode("utf-8")
            except UnicodeError:
                raise IntakeIssue("TEXT_ONLY") from None
            _need("\x00" not in text, "TEXT_ONLY")
            digest = gate._sha(raw)
            captured[row["path"]] = (len(raw), digest)
            files.append({**row, "sha256": digest, "bytes": len(raw)})
        context["captured"] = captured
        proposal = {"format": "outlands-source-export-proposal-v1", "family": selection["family"], "files": files}
        gate._proposal(proposal)
        proposal_raw = _json_raw(proposal)
        review = {"format": "outlands-source-export-review-v1", "family": selection["family"],
                  "proposal_sha256": gate._sha(proposal_raw), "publication_authorized": False,
                  "files": [{"path": row["path"], "sha256": row["sha256"], "artifact_kind": row["artifact_kind"],
                             **{key: "pending" for key in PENDING_FIELDS}} for row in files]}
        gate._review(review)
        review_raw = _json_raw(review)
        buffers = {"CLAIM.json": CLAIM_RAW, "proposal.json": proposal_raw, "review-draft.json": review_raw,
                   "CHECKLIST.md": CHECKLIST_RAW, "CHECKLIST.txt": CHECKLIST_RAW}
        _need(all(len(raw) <= gate.MAX_META for raw in buffers.values()), "INPUT_LIMIT")
        phase = "recheck"
        _recheck(context)
        _same_parent(context)
        os.mkdir(output.name, 0o700, dir_fd=parent)
        created = True
        packet = os.open(output.name, gate.DIR_FLAGS, dir_fd=parent)
        gate._private_dir(packet)
        phase = "write"
        for name in OUTPUT_FILES[:-1]:
            _write_new(packet, name, buffers[name])
            result["files_written"].append(name)
            if name == "review-draft.json":
                result["draft_created"] = True
        phase = "recheck"
        _recheck(context)
        _same_parent(context)
        _check_packet(context, packet, buffers)
        marker = {"format": "outlands-source-export-intake-complete-v1", "status": "HOLD",
                  "publication_authorized": False, "export_performed": False,
                  "files": {name: gate._sha(raw) for name, raw in buffers.items()}}
        phase = "write"
        _write_new(packet, OUTPUT_FILES[-1], _json_raw(marker))
        result["files_written"].append(OUTPUT_FILES[-1])
        result["complete_written"] = True
        result["bindings"] = {"format": "outlands-source-export-intake-bindings-v1",
            "selection_sha256": context["selection_pin"][1], "policy": {key + "_sha256": value[1] for key, value in policies.items()},
            "files": files, "proposal_sha256": gate._sha(proposal_raw), "review_draft_sha256": gate._sha(review_raw)}
        result["status"], result["reason_codes"] = "HOLD", ["REVIEW_PENDING"]
    except IntakeIssue as error:
        result["status"], result["reason_codes"] = "UNVERIFIABLE" if created else "REFUSED", [error.code]
    except gate.GateIssue as error:
        code = "SELECTION_SCHEMA" if phase == "selection" else "INPUT_CHANGED" if error.eligibility == "HOLD" else "INPUT_UNSAFE"
        result["status"], result["reason_codes"] = "UNVERIFIABLE" if created else "REFUSED", [code]
    except OSError:
        result["status"], result["reason_codes"] = "UNVERIFIABLE" if created else "REFUSED", ["OUTPUT_UNAVAILABLE" if created or phase == "write" else "INPUT_UNSAFE"]
    except (ValueError, TypeError, OverflowError, RecursionError):
        result["status"], result["reason_codes"] = "UNVERIFIABLE" if created else "REFUSED", ["INPUT_UNSAFE"]
    except Exception:
        result["status"], result["reason_codes"] = "UNVERIFIABLE" if created else "REFUSED", ["INTERNAL_REFUSAL"]
    finally:
        for fd in (packet, context.get("root_fd"), context.get("parent_fd")):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    result["status"], result["reason_codes"], result["bindings"] = "UNVERIFIABLE" if created else "REFUSED", ["OUTPUT_UNAVAILABLE"], None
    if result["status"] != "HOLD":
        result["bindings"] = None
    return result


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise IntakeIssue("CLI_ARGUMENTS")


def main(argv=None):
    os.umask(0o077)
    result = _result()
    try:
        parser = _Parser(prog="build-review-intake", allow_abbrev=False, description=__doc__)
        for flag in ("candidate", "selection", "output"):
            parser.add_argument("--" + flag, required=True)
        args = parser.parse_args(argv)
        result = build_intake(args.candidate, args.selection, args.output)
    except IntakeIssue as error:
        result["reason_codes"] = [error.code]
    summary = {key: value for key, value in result.items() if key != "bindings"}
    summary["format"] = "outlands-private-review-intake-cli-v1"
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 1 if result["status"] == "HOLD" else 2


if __name__ == "__main__":
    raise SystemExit(main())
