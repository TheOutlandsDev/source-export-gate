"""Read-only consistency/freshness of a pending v0.9 intake; never approval."""
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


def _packet(path):
    fd = gate._open_dir(path)
    try:
        before = gate._identity(gate._private_dir(fd))
        names = set()
        with os.scandir(fd) as entries:
            for entry in entries:
                names.add(entry.name)
                need(len(names) <= 6, "PACKET_MEMBERS")
        need(names == set(builder.OUTPUT_FILES), "PACKET_INCOMPLETE")
        data, pins = {}, {}
        for name in sorted(names):
            data[name], pins[name] = gate._read_at(fd, name, gate.MAX_META, {0o600})
        need(len({pin[:2] for pin in pins.values()}) == 6, "PACKET_ALIAS")
        need(data["CLAIM.json"] == builder.CLAIM_RAW, "PACKET_CLAIM")
        need(data["CHECKLIST.md"] == data["CHECKLIST.txt"] == builder.CHECKLIST_RAW, "PACKET_NOTES")
        marker = gate._parse(data["INTAKE-COMPLETE.json"])
        need(gate._exact(marker, {"format", "status", "publication_authorized", "export_performed", "files"})
             and marker["format"] == "outlands-source-export-intake-complete-v1"
             and marker["status"] == "HOLD" and marker["publication_authorized"] is False
             and marker["export_performed"] is False
             and marker["files"] == {n: gate._sha(data[n]) for n in builder.OUTPUT_FILES[:-1]}, "PACKET_HASHES")
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
        need(gate._identity(os.fstat(fd)) == before, "PACKET_CHANGED")
        named = gate._open_dir(path)
        try:
            need(gate._identity(gate._private_dir(named)) == before, "PACKET_CHANGED")
        finally:
            os.close(named)
        return {"directory": before, "pins": pins, "data": data}, proposal
    finally:
        os.close(fd)


def verify_intake(candidate_root, selection_path, intake_path):
    result = {"format": "outlands-review-intake-verification-v1", "status": "DAMAGED",
              "reason_codes": [], "review_status": "PENDING", "eligibility": "HOLD",
              "content_reads": 0, "selected_files": 0, "publication_status": "HELD",
              "publication_authorized": False, "export_performed": False,
              "destination_verified": False, "git_metadata_reviewed": False, "scanner_called": False}
    root, phase = None, "packet"
    try:
        candidate, selection_path, intake = map(gate._absolute, (candidate_root, selection_path, intake_path))
        builder._locations(candidate, selection_path, intake)
        # Fully validate the six metadata members before candidate root access.
        saved, proposal = _packet(intake)
        phase = "selection"
        selection_raw, selection_pin = gate._read_control(selection_path)
        selection = gate._parse(selection_raw)
        builder._selection(selection)
        expected = [{k: row[k] for k in ("path", "artifact_kind", "synthetic_fixture")} for row in proposal["files"]]
        need(selection["family"] == proposal["family"] and selection["files"] == expected, "SELECTION_CHANGED")
        result["selected_files"] = len(expected)
        phase = "candidate"
        root = gate._open_dir(candidate)
        context = {"root_fd": root, "candidate": candidate, "selection": selection,
                   "selection_pin": (selection_pin, gate._sha(selection_raw)),
                   "policies": builder._policy_snapshot(), "parent_pin": saved["directory"]}
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
    except VerifyIssue as error:
        result["status"] = "STALE" if phase in {"selection", "candidate"} else "DAMAGED"
        result["reason_codes"] = [error.code]
    except (gate.GateIssue, builder.IntakeIssue, OSError, ValueError, TypeError, OverflowError, RecursionError):
        result["status"] = "STALE" if phase in {"selection", "candidate"} else "DAMAGED"
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
        a = parser.parse_args(argv)
    except VerifyIssue:
        print(json.dumps({"format": "outlands-review-intake-verification-v1", "status": "DAMAGED", "reason_codes": ["CLI_ARGUMENTS"], "eligibility": "HOLD", "publication_authorized": False, "export_performed": False}))
        return 2
    result = verify_intake(a.candidate, a.selection, a.intake)
    print(json.dumps(result, sort_keys=True))
    return 1 if result["status"] == "CONSISTENT" else 2


if __name__ == "__main__":
    raise SystemExit(main())
