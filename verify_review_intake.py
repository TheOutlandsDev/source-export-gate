"""Read-only pending intake checks, with explicit v2 bindings and v1 limits."""
import argparse
import importlib.util
import json
import os
from pathlib import Path

_spec = importlib.util.spec_from_file_location("outlands_intake", Path(__file__).absolute().with_name("build_review_intake.py"))
builder = importlib.util.module_from_spec(_spec)
exec(compile(_spec.loader.get_source(_spec.name), _spec.origin, "exec"), builder.__dict__)
gate = builder.gate


class VerifyIssue(Exception):
    def __init__(self, code):
        self.code = code


def need(value, code):
    if not value:
        raise VerifyIssue(code)


def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _evidence(data, proposal):
    value = gate._parse(data["evidence-bindings.json"])
    need(gate._exact(value, {"format", "selection_sha256", "policy", "files",
                            "proposal_sha256", "review_draft_sha256"})
         and value["format"] == "outlands-source-export-intake-bindings-v1"
         and _digest(value["selection_sha256"])
         and gate._exact(value["policy"], {"gate_sha256", "intake_sha256"})
         and all(_digest(v) for v in value["policy"].values())
         and builder._json_raw(value["files"]) == builder._json_raw(proposal["files"])
         and value["proposal_sha256"] == gate._sha(data["proposal.json"])
         and value["review_draft_sha256"] == gate._sha(data["review-draft.json"]), "BINDINGS_INVALID")
    return value


def _packet(path):
    fd = gate._open_dir(path)
    try:
        before = gate._identity(gate._private_dir(fd))
        names = set()
        with os.scandir(fd) as entries:
            for entry in entries:
                names.add(entry.name)
                need(len(names) <= len(builder.OUTPUT_FILES), "PACKET_MEMBERS")
        need(names in (set(builder.OUTPUT_FILES), set(builder.LEGACY_OUTPUT_FILES)), "PACKET_INCOMPLETE")
        data, pins = {}, {}
        for name in sorted(names):
            data[name], pins[name] = gate._read_at(fd, name, gate.MAX_META, {0o600})
        need(len({pin[:2] for pin in pins.values()}) == len(names), "PACKET_ALIAS")
        need(data["CLAIM.json"] == builder.CLAIM_RAW, "PACKET_CLAIM")
        need(data["CHECKLIST.md"] == data["CHECKLIST.txt"] == builder.CHECKLIST_RAW, "PACKET_NOTES")
        marker = gate._parse(data["INTAKE-COMPLETE.json"])
        need(type(marker) is dict, "PACKET_VERSION")
        version = marker.get("format")
        need(version in {"outlands-source-export-intake-complete-v1",
                         "outlands-source-export-intake-complete-v2"}, "PACKET_VERSION")
        members = builder.OUTPUT_FILES if version.endswith("-v2") else builder.LEGACY_OUTPUT_FILES
        need(names == set(members), "PACKET_INCOMPLETE")
        need(gate._exact(marker, {"format", "status", "publication_authorized", "export_performed", "files"})
             and marker["status"] == "HOLD" and marker["publication_authorized"] is False
             and marker["export_performed"] is False
             and marker["files"] == {n: gate._sha(data[n]) for n in members[:-1]}, "PACKET_HASHES")
        proposal, review = gate._parse(data["proposal.json"]), gate._parse(data["review-draft.json"])
        gate._proposal(proposal)
        gate._review(review)
        need(review["family"] == proposal["family"] and review["proposal_sha256"] == gate._sha(data["proposal.json"])
             and len(review["files"]) == len(proposal["files"]), "REVIEW_BINDING")
        for row, assertion in zip(proposal["files"], review["files"]):
            need(all(row[k] == assertion[k] for k in ("path", "sha256", "artifact_kind"))
                 and all(assertion[k] == "pending" for k in builder.PENDING_FIELDS), "REVIEW_NOT_PENDING")
            need(row["artifact_kind"] in gate.ELIGIBLE_KINDS and gate._path_eligible(row["path"])
                 and (row["artifact_kind"] != "synthetic_example" or row["synthetic_fixture"] is True), "PROPOSAL_INELIGIBLE")
        evidence = _evidence(data, proposal) if version.endswith("-v2") else None
        need(gate._identity(os.fstat(fd)) == before, "PACKET_CHANGED")
        named = gate._open_dir(path)
        try:
            need(gate._identity(gate._private_dir(named)) == before, "PACKET_CHANGED")
        finally:
            os.close(named)
        return {"directory": before, "pins": pins, "data": data,
                "packet_format": version, "evidence": evidence}, proposal
    finally:
        os.close(fd)


def verify_intake(candidate_root, selection_path, intake_path, *, require_bindings=False):
    result = {"format": "outlands-review-intake-verification-v1", "status": "DAMAGED",
              "reason_codes": [], "review_status": "PENDING", "eligibility": "HOLD",
              "content_reads": 0, "selected_files": 0, "publication_status": "HELD",
              "publication_authorized": False, "export_performed": False,
              "destination_verified": False, "git_metadata_reviewed": False, "scanner_called": False,
              "packet_format": None, "bindings_status": "UNVERIFIABLE",
              "limitations": ["UNSIGNED_OWNER_STORAGE"]}
    root, phase = None, "packet"
    try:
        need(type(require_bindings) is bool, "BINDINGS_MODE")
        candidate, selection_path, intake = map(gate._absolute, (candidate_root, selection_path, intake_path))
        builder._locations(candidate, selection_path, intake)
        # Validate the complete packet and bindings before candidate root access.
        saved, proposal = _packet(intake)
        evidence = saved["evidence"]
        result["packet_format"] = saved["packet_format"]
        if evidence is None:
            result["bindings_status"] = "LEGACY_UNBOUND"
            result["limitations"] += ["EXACT_SELECTION_UNBOUND", "HISTORICAL_POLICY_UNBOUND"]
        need(not require_bindings or evidence is not None, "BINDINGS_REQUIRED")
        phase = "selection"
        selection_raw, selection_pin = gate._read_control(selection_path)
        selection = gate._parse(selection_raw)
        builder._selection(selection)
        expected = [{k: row[k] for k in ("path", "artifact_kind", "synthetic_fixture")} for row in proposal["files"]]
        need(selection["family"] == proposal["family"] and selection["files"] == expected, "SELECTION_CHANGED")
        result["selected_files"] = len(expected)
        phase = "bindings"
        if evidence is not None:
            need(gate._sha(selection_raw) == evidence["selection_sha256"], "SELECTION_BYTES_CHANGED")
        policies = builder._policy_snapshot()
        if evidence is not None:
            need({key + "_sha256": value[1] for key, value in policies.items()} == evidence["policy"],
                 "POLICY_CHANGED")
        phase = "candidate"
        root = gate._open_dir(candidate)
        context = {"root_fd": root, "candidate": candidate, "selection": selection,
                   "selection_pin": (selection_pin, gate._sha(selection_raw)),
                   "policies": policies, "parent_pin": saved["directory"]}
        metadata = builder._selected_metadata(context)
        need(all(metadata["files"][r["path"]][6] == r["bytes"] for r in proposal["files"]), "SIZE_CHANGED")
        for row in proposal["files"]:
            result["content_reads"] += 1
            raw = gate._read_member(root, row["path"], metadata["files"][row["path"]], gate.MAX_FILE)
            need(len(raw) == row["bytes"] and gate._sha(raw) == row["sha256"], "HASH_CHANGED")
            need("\x00" not in raw.decode("utf-8"), "TEXT_CHANGED")
        need(builder._selected_metadata(context) == metadata, "INPUT_CHANGED")
        current, pin = gate._read_control(selection_path, expected_pin=selection_pin)
        need(pin == selection_pin and current == selection_raw, "SELECTION_CHANGED")
        need(builder._policy_snapshot(context["policies"]) == context["policies"], "POLICY_CHANGED")
        phase = "packet"
        final, _ = _packet(intake)
        need(final == saved, "PACKET_CHANGED")
        result["status"], result["reason_codes"] = "CONSISTENT", ["REVIEW_PENDING"]
        if evidence is not None:
            result["bindings_status"] = "MATCHED"
    except VerifyIssue as error:
        result["status"] = "STALE" if phase in {"selection", "bindings", "candidate"} else "DAMAGED"
        result["reason_codes"] = [error.code]
    except (gate.GateIssue, builder.IntakeIssue, OSError, ValueError, TypeError, OverflowError, RecursionError):
        result["status"] = "STALE" if phase in {"selection", "bindings", "candidate"} else "DAMAGED"
        result["reason_codes"] = ["INPUT_UNAVAILABLE" if phase != "packet" else "PACKET_INVALID"]
    except Exception:
        result["status"], result["reason_codes"] = "DAMAGED", ["VERIFICATION_REFUSED"]
    finally:
        if root is not None:
            try:
                os.close(root)
            except OSError:
                result["status"], result["reason_codes"] = "DAMAGED", ["CLOSE_UNCERTAIN"]
    return result


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise VerifyIssue("CLI_ARGUMENTS")


def main(argv=None):
    try:
        parser = Parser(allow_abbrev=False, description=__doc__)
        for name in ("candidate", "selection", "intake"):
            parser.add_argument("--" + name, required=True)
        parser.add_argument("--require-bindings", action="store_true",
                            help="Refuse legacy packets without exact selection and policy bindings.")
        a = parser.parse_args(argv)
    except VerifyIssue:
        print(json.dumps({"format": "outlands-review-intake-verification-v1", "status": "DAMAGED", "reason_codes": ["CLI_ARGUMENTS"], "eligibility": "HOLD", "publication_authorized": False, "export_performed": False}))
        return 2
    result = verify_intake(a.candidate, a.selection, a.intake, require_bindings=a.require_bindings)
    print(json.dumps(result, sort_keys=True))
    return 1 if result["status"] == "CONSISTENT" else 2


if __name__ == "__main__":
    raise SystemExit(main())
