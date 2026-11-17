"""Invented-only export eligibility regressions; no real source or publication.

Every fixture is a fresh private temporary tree. Scanner handoff tests replace
only the documented pure screening seam; no scanner/provider/process is run.
"""

from contextlib import ExitStack, contextmanager, redirect_stdout
import copy
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import source_export_gate as gate


FAMILIES = ("code-atlas", "java-python-kits", "coding-agent-methods", "agent-workbench",
            "wow-rebuild", "game-tools-ott", "workflow-lab", "blueprint-methods")
INELIGIBLE = ("log", "runtime_record", "configuration", "credential", "database", "backup", "archive",
              "patch", "git_metadata", "model_data", "employer_material", "client_material", "unknown")
FIELDS = {"format", "eligibility", "reason_codes", "family", "proposed_files", "observed_files", "content_reads",
          "scanner_called", "text_review", "findings", "publication_status", "publication_authorized",
          "export_performed", "destination_verified", "git_metadata_reviewed", "bindings"}
INVENTED = b"# Invented source-export fixture. Never executed.\nanswer = 7\n"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def write_private(path, raw):
    missing = []
    parent = path.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
    if path.exists():
        path.write_bytes(raw)
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
    path.chmod(0o600)


@contextmanager
def fixture(*, family=FAMILIES[0], files=None, kinds=None, synthetic=False):
    files = {"src/example.py": INVENTED} if files is None else dict(files)
    kinds = {} if kinds is None else kinds
    with tempfile.TemporaryDirectory(prefix="invented-export-gate-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        candidate, metadata = root / "candidate", root / "metadata"
        candidate.mkdir(mode=0o700)
        metadata.mkdir(mode=0o700)
        for name, raw in files.items():
            write_private(candidate / name, raw)
        proposal = {"format": "outlands-source-export-proposal-v1", "family": family, "files": [
            {"path": name, "sha256": digest(raw), "bytes": len(raw), "artifact_kind": kinds.get(name, "source"),
             "synthetic_fixture": synthetic} for name, raw in sorted(files.items())]}
        proposal_path, review_path = metadata / "proposal.json", metadata / "review.json"
        raw = canonical(proposal)
        review = {"format": "outlands-source-export-review-v1", "family": family, "proposal_sha256": digest(raw),
                  "publication_authorized": False, "files": [
            {"path": row["path"], "sha256": row["sha256"], "artifact_kind": row["artifact_kind"],
             "decision": "eligible", "source_authority": "reviewed", "ownership": "reviewed",
             "confidentiality": "reviewed", "rights": "reviewed", "notices": "preserved"}
            for row in proposal["files"]]}
        write_private(proposal_path, raw)
        write_private(review_path, canonical(review))
        yield SimpleNamespace(root=root, candidate=candidate, metadata=metadata, files=files,
                              proposal=proposal, review=review, proposal_path=proposal_path, review_path=review_path)


def save_review(case):
    write_private(case.review_path, canonical(case.review))


def save_proposal(case, *, rebind=True):
    raw = canonical(case.proposal)
    write_private(case.proposal_path, raw)
    if rebind:
        case.review["proposal_sha256"] = digest(raw)
        save_review(case)


def inventory_bytes(root):
    """Observe only this test's own regular files/directories, never follow links."""
    rows = {}
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        value = [stat.S_IMODE(info.st_mode), info.st_uid, info.st_nlink]
        if stat.S_ISREG(info.st_mode):
            raw = path.read_bytes()
            value += [len(raw), digest(raw)]
        elif stat.S_ISLNK(info.st_mode):
            value += ["symbolic-link"]
        rows[path.relative_to(root).as_posix()] = value
    return rows


def synthetic_screen_pins(scanner, terms):
    """Only for a deliberately mocked screen; preserve actual control pins."""
    result = {}
    for key, path in (("scanner", scanner), ("terms", terms)):
        raw, pin = gate._read_control(path, 65536, trusted_code=key == "scanner")
        result[key] = (pin, digest(raw))
    return result


class SourceExportGateTests(unittest.TestCase):
    def setUp(self):
        self.guards = ExitStack()
        self.addCleanup(self.guards.close)
        self.denied = []
        for target in ("socket.socket", "socket.create_connection", "subprocess.Popen", "subprocess.run",
                       "os.execve", "os.system", "os.posix_spawn", "os.posix_spawnp", "os.fork"):
            self.denied.append(self.guards.enter_context(patch(target, side_effect=AssertionError("external action forbidden"))))

    def tearDown(self):
        for denied in self.denied:
            denied.assert_not_called()

    def assess(self, case, **kwargs):
        result = gate.assess(case.candidate, case.proposal_path, case.review_path, **kwargs)
        self.assertEqual(set(result), FIELDS)
        self.assertEqual(result["format"], "outlands-source-export-result-v2")
        self.assertTrue(result["bindings"] is None or type(result["bindings"]) is dict)
        self.assertIn(result["eligibility"], {"ELIGIBLE_FOR_TEXT_REVIEW", "HOLD", "REFUSED"})
        self.assertIn(result["family"], (*FAMILIES, None))
        for key in ("proposed_files", "observed_files", "content_reads"):
            self.assertIs(type(result[key]), int)
            self.assertGreaterEqual(result[key], 0)
        self.assertIs(type(result["scanner_called"]), bool)
        self.assertIn(result["text_review"], {"NOT_RUN", "PASS", "REVIEW"})
        self.assertIs(type(result["reason_codes"]), list)
        for reason in result["reason_codes"]:
            self.assertRegex(reason, r"^[A-Z][A-Z0-9_]{0,63}$")
        self.assertIs(type(result["findings"]), list)
        for finding in result["findings"]:
            self.assertEqual(set(finding), {"path", "check"})
            self.assertIs(type(finding["path"]), str)
            self.assertIs(type(finding["check"]), str)
        self.assertEqual(result["publication_status"], "HELD")
        for key in ("publication_authorized", "export_performed", "destination_verified", "git_metadata_reviewed"):
            self.assertIs(result[key], False)
        return result

    def blocked_before_content(self, case, expected="HOLD"):
        with patch.object(gate, "_read_member", side_effect=AssertionError("candidate content read before eligibility")) as reads, \
                patch.object(gate, "_screen_snapshot", side_effect=AssertionError("scanner reached before eligibility")) as screen:
            result = self.assess(case)
        self.assertEqual(result["eligibility"], expected)
        self.assertEqual(result["content_reads"], 0)
        self.assertIs(result["scanner_called"], False)
        self.assertEqual(result["text_review"], "NOT_RUN")
        self.assertEqual(result["findings"], [])
        self.assertIsNone(result["bindings"])
        self.assertTrue(result["reason_codes"])
        reads.assert_not_called()
        screen.assert_not_called()
        return result

    def test_approved_source_for_each_of_eight_families_is_readonly_and_never_authorizes_publication(self):
        for family in FAMILIES:
            with self.subTest(family=family), fixture(family=family) as case:
                before = inventory_bytes(case.root)
                with patch.object(gate, "_screen_snapshot", side_effect=AssertionError("eligibility-only reached scanner")) as screen:
                    result = self.assess(case)
                self.assertEqual(result["eligibility"], "ELIGIBLE_FOR_TEXT_REVIEW")
                self.assertEqual(result["family"], family)
                self.assertEqual((result["proposed_files"], result["observed_files"], result["content_reads"]), (1, 1, 1))
                self.assertEqual(result["text_review"], "NOT_RUN")
                screen.assert_not_called()
                self.assertEqual(inventory_bytes(case.root), before)

    def test_all_eligible_kinds_and_reviewed_build_notice_examples_remain_possible(self):
        examples = [("src/example.py", "source", False), ("README.md", "documentation", False),
                    ("examples/sample.json", "synthetic_example", True), ("NOTICE.txt", "notice", False),
                    ("CMakeLists.txt", "source", False), ("build.gradle", "source", False)]
        for name, kind, synthetic in examples:
            with self.subTest(name=name), fixture(files={name: INVENTED}, kinds={name: kind}, synthetic=synthetic) as case:
                self.assertEqual(self.assess(case)["eligibility"], "ELIGIBLE_FOR_TEXT_REVIEW")

    def test_bland_ineligible_artifact_kinds_stay_held_even_when_marked_synthetic(self):
        for kind in INELIGIBLE:
            with self.subTest(kind=kind), fixture(synthetic=True) as case:
                case.proposal["files"][0]["artifact_kind"] = kind
                case.review["files"][0]["artifact_kind"] = kind
                save_proposal(case)
                self.blocked_before_content(case)

    def test_runtime_log_patch_mislabels_and_synthetic_flags_cannot_bypass_paths(self):
        paths = ("ordinary.log", "ordinary.diff", "ordinary.patch", "runtime/status.json", "logs/plain.txt",
                 "runs/plain.py", "data/plain.py", "backup/plain.py", "exports/plain.py", "credentials/plain.py",
                 "secret/plain.py", "cache/plain.py", ".git/config", ".github/workflows/plain.yml", ".env",
                 ".env.example", "server-info.json", "result.json", "hold.json", "state.json")
        for name in paths:
            for kind in ("source", "synthetic_example"):
                with self.subTest(path=name, kind=kind), fixture(files={name: b"Invented bland text.\n"},
                         kinds={name: kind}, synthetic=True) as case:
                    self.blocked_before_content(case)

    def test_case_insensitive_dangerous_suffixes_and_directories_remain_ineligible(self):
        paths = ("LOGS/plain.txt", "RUNTIME/plain.py", "DATA/plain.py", "CACHE/plain.py", "SECRETS/plain.py",
                 "plain.LOG", "plain.DIFF", "plain.SQLITE3", "plain.DB", "plain.ZIP", "plain.TAR.GZ",
                 "plain.PEM", "plain.KEY", "plain.PYC", "plain.EXE", "plain.SO", "plain.CLASS", ".ENV.local")
        for name in paths:
            with self.subTest(path=name), fixture(files={name: INVENTED}, synthetic=True) as case:
                self.blocked_before_content(case)

    def test_synthetic_example_requires_true_but_other_eligible_kinds_do_not(self):
        with fixture(kinds={"src/example.py": "synthetic_example"}, synthetic=False) as case:
            self.blocked_before_content(case)

    def test_env_suffixes_and_sqlite_companions_hold_despite_source_or_synthetic_labels(self):
        paths = ("App.EnV", "APP.eNv.LoCaL", "cache.SQLITE-wal", "cache.sqlite-SHM",
                 "cache.SQLITE-journal", "db.Sqlite3-WaL", "copy.SQLITE.backup", ".SqLiTe-WaL")
        for name in paths:
            for kind in ("source", "synthetic_example"):
                with self.subTest(path=name, kind=kind), fixture(
                        files={name: b"Invented bland portable text. Never executed.\n"},
                        kinds={name: kind}, synthetic=True) as case:
                    result = self.blocked_before_content(case)
                    self.assertIs(result["publication_authorized"], False)
                    self.assertIs(result["export_performed"], False)
                    self.assertIs(result["destination_verified"], False)
                    self.assertIs(result["git_metadata_reviewed"], False)

    def test_known_unsettled_review_statuses_hold_every_review_dimension(self):
        for field in ("decision", "source_authority", "ownership", "confidentiality", "rights", "notices"):
            for status in ("unknown", "pending", "hold", "excluded"):
                with self.subTest(field=field, status=status), fixture() as case:
                    case.review["files"][0][field] = status
                    save_review(case)
                    self.blocked_before_content(case)

    def test_valid_but_mismatched_proposal_family_hash_row_hash_kind_and_path_hold(self):
        changes = [("family", FAMILIES[1]), ("proposal_sha256", "0" * 64), ("sha256", "0" * 64),
                   ("artifact_kind", "documentation"), ("path", "src/different.py")]
        for field, value in changes:
            with self.subTest(field=field), fixture() as case:
                target = case.review if field in {"family", "proposal_sha256"} else case.review["files"][0]
                target[field] = value
                save_review(case)
                self.blocked_before_content(case)

    def test_review_path_set_cannot_add_or_omit_a_proposed_member(self):
        for change in ("extra", "missing"):
            with self.subTest(change=change), fixture(files={"a.py": INVENTED, "b.py": INVENTED}) as case:
                if change == "extra":
                    row = copy.deepcopy(case.review["files"][-1]); row["path"] = "c.py"
                    case.review["files"].append(row)
                else:
                    case.review["files"].pop()
                save_review(case)
                self.blocked_before_content(case)

    def test_review_binds_exact_raw_proposal_bytes_not_a_reencoded_object(self):
        with fixture() as case:
            write_private(case.proposal_path, case.proposal_path.read_bytes() + b" ")
            self.blocked_before_content(case)

    def test_proposal_exact_fields_and_types_are_required_before_content(self):
        changes = [("root-extra", None), ("root-missing", None), ("row-extra", None), ("row-missing", None),
                   ("bytes", True), ("bytes", -1), ("bytes", 1.0), ("sha256", "A" * 64),
                   ("sha256", "short"), ("synthetic_fixture", 1), ("artifact_kind", True), ("artifact_kind", "invented-new-kind")]
        for field, value in changes:
            with self.subTest(field=field, value=value), fixture() as case:
                if field == "root-extra": case.proposal["private_note"] = "INVENTED private marker"
                elif field == "root-missing": del case.proposal["family"]
                elif field == "row-extra": case.proposal["files"][0]["note"] = "INVENTED private marker"
                elif field == "row-missing": del case.proposal["files"][0]["synthetic_fixture"]
                else: case.proposal["files"][0][field] = value
                save_proposal(case)
                self.blocked_before_content(case, "REFUSED")

    def test_review_exact_fields_and_types_and_no_publication_override(self):
        changes = [("root-extra", None), ("root-missing", None), ("row-extra", None), ("row-missing", None),
                   ("publication_authorized", True), ("publication_authorized", 0), ("proposal_sha256", None),
                   ("ownership", True), ("decision", "APPROVED_BY_MAGIC"), ("notices", "arbitrary-notice-status")]
        for field, value in changes:
            with self.subTest(field=field, value=value), fixture() as case:
                if field == "root-extra": case.review["reviewer_identity"] = "INVENTED identity"
                elif field == "root-missing": del case.review["proposal_sha256"]
                elif field == "row-extra": case.review["files"][0]["private_note"] = "INVENTED private marker"
                elif field == "row-missing": del case.review["files"][0]["rights"]
                elif field in {"publication_authorized", "proposal_sha256"}: case.review[field] = value
                else: case.review["files"][0][field] = value
                save_review(case)
                self.blocked_before_content(case, "REFUSED")

    def test_unknown_family_and_unsorted_or_duplicate_rows_are_refused(self):
        for target in ("proposal", "review"):
            for mutation in ("family", "reverse", "duplicate"):
                with self.subTest(target=target, mutation=mutation), fixture(files={"a.py": INVENTED, "b.py": INVENTED}) as case:
                    value = getattr(case, target)
                    if mutation == "family": value["family"] = "invented-unregistered-family"
                    elif mutation == "reverse": value["files"].reverse()
                    else: value["files"].append(copy.deepcopy(value["files"][-1]))
                    save_proposal(case) if target == "proposal" else save_review(case)
                    self.blocked_before_content(case, "REFUSED")

    def test_malformed_duplicate_nonfinite_utf8_and_nul_json_inputs_refuse(self):
        invalid = (b"{", b"\xff", b"{}\x00", b"{} trailing", b'{"format":1,"format":2}',
                   b'{"private":NaN}', b'{"private":Infinity}', b'{"private":-Infinity}')
        for target in ("proposal_path", "review_path"):
            for index, raw in enumerate(invalid):
                with self.subTest(target=target, case=index), fixture() as case:
                    write_private(getattr(case, target), raw)
                    self.blocked_before_content(case, "REFUSED")

    def test_metadata_json_exact_limit_is_accepted_and_over_limit_refuses(self):
        for target in ("proposal_path", "review_path"):
            for extra in (0, 1):
                with self.subTest(target=target, extra=extra), fixture() as case:
                    path = getattr(case, target)
                    raw = path.read_bytes(); raw += b" " * (262144 + extra - len(raw))
                    write_private(path, raw)
                    if target == "proposal_path":
                        case.review["proposal_sha256"] = digest(raw); save_review(case)
                    if extra: self.blocked_before_content(case, "REFUSED")
                    else: self.assertEqual(self.assess(case)["eligibility"], "ELIGIBLE_FOR_TEXT_REVIEW")

    def test_strict_path_syntax_refuses_before_any_candidate_read(self):
        invalid = ("../outside.py", "/absolute.py", "src/../example.py", "src//example.py", "src\\example.py",
                   "src/./example.py", "src/", "", "source with space.py", "\u03bb.py", "x" * 241,
                   "/".join(["n"] * 8 + ["example.py"]))
        for name in invalid:
            with self.subTest(path=name), fixture() as case:
                case.proposal["files"][0]["path"] = case.review["files"][0]["path"] = name
                save_proposal(case)
                self.blocked_before_content(case, "REFUSED")

    def test_maximum_path_bytes_and_depth_are_supported_for_approved_source(self):
        for name in ("x" * 240, "/".join(["n"] * 7 + ["example.py"])):
            with self.subTest(path=name), fixture(files={name: INVENTED}) as case:
                self.assertEqual(self.assess(case)["eligibility"], "ELIGIBLE_FOR_TEXT_REVIEW")

    def test_extra_missing_and_unexpected_empty_candidate_members_hold_without_reads(self):
        for change in ("extra-file", "missing-file", "extra-directory"):
            with self.subTest(change=change), fixture() as case:
                if change == "extra-file": write_private(case.candidate / "extra.py", INVENTED)
                elif change == "missing-file": (case.candidate / "src/example.py").unlink()
                else: (case.candidate / "extra").mkdir(mode=0o700)
                self.blocked_before_content(case)

    def test_symlink_hardlink_and_fifo_members_hold_without_content_reads(self):
        for kind in ("symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind), fixture(files={"pipe.py": INVENTED}) as case:
                member = case.candidate / "pipe.py"
                outside = case.root / "invented-outside.py"; write_private(outside, INVENTED)
                member.unlink()
                if kind == "symlink": member.symlink_to(outside)
                elif kind == "hardlink": os.link(outside, member)
                else: os.mkfifo(member, 0o600)
                real_open = os.open
                def safe_open(path, flags, *args, **kwargs):
                    if str(path) in {str(member), "pipe.py"} and not flags & getattr(os, "O_PATH", 0):
                        raise AssertionError("unsafe member opened for content")
                    return real_open(path, flags, *args, **kwargs)
                with patch.object(gate.os, "open", side_effect=safe_open):
                    self.blocked_before_content(case)

    def test_candidate_file_root_and_subdirectory_permissions_are_private(self):
        for target in ("file", "root", "directory"):
            with self.subTest(target=target), fixture() as case:
                path = {"file": case.candidate / "src/example.py", "root": case.candidate,
                        "directory": case.candidate / "src"}[target]
                path.chmod(0o644 if target == "file" else 0o755)
                self.blocked_before_content(case)

    def test_private_input_mode_parent_link_and_absent_input_refuse(self):
        for mutation in ("proposal-mode", "review-mode", "parent-mode", "proposal-link", "review-missing"):
            with self.subTest(mutation=mutation), fixture() as case:
                if mutation == "proposal-mode": case.proposal_path.chmod(0o644)
                elif mutation == "review-mode": case.review_path.chmod(0o644)
                elif mutation == "parent-mode": case.metadata.chmod(0o755)
                elif mutation == "proposal-link": os.link(case.proposal_path, case.root / "invented-proposal-alias")
                else: case.review_path.unlink()
                with patch.object(gate, "_inventory", side_effect=AssertionError("candidate inventoried before private input validation")):
                    self.blocked_before_content(case, "REFUSED")

    def test_symlink_in_absolute_metadata_path_components_is_refused(self):
        with fixture() as case:
            alias = case.root / "metadata-alias"; alias.symlink_to(case.metadata, target_is_directory=True)
            case.proposal_path = alias / "proposal.json"
            self.blocked_before_content(case, "REFUSED")

    def test_metadata_inputs_inside_candidate_are_refused_before_inventory(self):
        for target in ("proposal_path", "review_path"):
            with self.subTest(target=target), fixture() as case:
                original = getattr(case, target)
                inside = case.candidate / original.name
                write_private(inside, original.read_bytes())
                setattr(case, target, inside)
                with patch.object(gate, "_inventory", side_effect=AssertionError("input boundary checked too late")):
                    self.blocked_before_content(case, "REFUSED")

    def test_matching_size_but_changed_content_or_declared_hash_holds_after_read(self):
        for change in ("content", "hash"):
            with self.subTest(change=change), fixture() as case:
                if change == "content": write_private(case.candidate / "src/example.py", INVENTED.replace(b"7", b"8"))
                else:
                    case.proposal["files"][0]["sha256"] = case.review["files"][0]["sha256"] = "0" * 64
                    save_proposal(case)
                with patch.object(gate, "_screen_snapshot", side_effect=AssertionError("changed content reached scanner")):
                    result = self.assess(case)
                self.assertEqual(result["eligibility"], "HOLD")
                self.assertEqual(result["content_reads"], 1)
                self.assertFalse(result["scanner_called"])

    def test_invalid_utf8_and_nul_content_stay_held_without_scanning(self):
        for raw in (b"\xff", b"Invented\x00source\n"):
            with self.subTest(raw=raw), fixture(files={"example.py": raw}) as case:
                with patch.object(gate, "_screen_snapshot", side_effect=AssertionError("binary content reached scanner")):
                    result = self.assess(case)
                self.assertEqual(result["eligibility"], "HOLD")
                self.assertEqual(result["content_reads"], 1)
                self.assertFalse(result["scanner_called"])

    def test_exact_file_and_aggregate_byte_bounds_and_overflow(self):
        for sizes, eligible in [([2000000], True), ([2000001], False), ([2000000] * 4, True), ([2000000] * 4 + [1], False)]:
            with self.subTest(sizes=sizes), fixture(files={"f%02d.py" % i: b"x" * size for i, size in enumerate(sizes)}) as case:
                if eligible: self.assertEqual(self.assess(case)["eligibility"], "ELIGIBLE_FOR_TEXT_REVIEW")
                else: self.blocked_before_content(case, "REFUSED")

    def test_exact_128_proposed_files_and_129_file_overflow(self):
        for count in (128, 129):
            with self.subTest(count=count), fixture(files={"f%03d.py" % i: INVENTED for i in range(count)}) as case:
                if count == 128:
                    result = self.assess(case)
                    self.assertEqual((result["eligibility"], result["content_reads"]), ("ELIGIBLE_FOR_TEXT_REVIEW", 128))
                else: self.blocked_before_content(case, "REFUSED")

    def test_bounded_inventory_rejects_excess_entries_before_member_reads(self):
        with fixture() as case:
            for index in range(513): (case.candidate / ("empty-%03d" % index)).mkdir(mode=0o700)
            self.blocked_before_content(case)

    def test_file_drift_between_inventory_and_read_is_not_eligible(self):
        with fixture() as case:
            original = gate._read_member
            def drift(*args, **kwargs):
                write_private(case.candidate / "src/example.py", INVENTED.replace(b"7", b"8"))
                return original(*args, **kwargs)
            with patch.object(gate, "_read_member", side_effect=drift), \
                    patch.object(gate, "_screen_snapshot", side_effect=AssertionError("drift reached scanner")):
                result = self.assess(case)
            self.assertEqual(result["eligibility"], "HOLD")
            self.assertFalse(result["scanner_called"])

    def test_final_inventory_detects_drift_after_content_capture(self):
        with fixture() as case:
            original = gate._inventory
            calls = 0
            def drift(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2: write_private(case.candidate / "src/example.py", INVENTED.replace(b"7", b"8"))
                return original(*args, **kwargs)
            with patch.object(gate, "_inventory", side_effect=drift), \
                    patch.object(gate, "_screen_snapshot", side_effect=AssertionError("late drift reached scanner")):
                result = self.assess(case)
            self.assertEqual(result["eligibility"], "HOLD")
            self.assertGreaterEqual(calls, 2)
            self.assertGreater(result["content_reads"], 0)
            self.assertFalse(result["scanner_called"])

    def test_final_input_guard_detects_changed_proposal_and_review_bytes(self):
        for target in ("proposal_path", "review_path"):
            with self.subTest(target=target), fixture() as case:
                original = gate._recheck_inputs
                def drift(*args, **kwargs):
                    path = getattr(case, target); write_private(path, path.read_bytes() + b" ")
                    return original(*args, **kwargs)
                with patch.object(gate, "_recheck_inputs", side_effect=drift), \
                        patch.object(gate, "_screen_snapshot", side_effect=AssertionError("changed inputs reached scanner")):
                    result = self.assess(case)
                self.assertEqual(result["eligibility"], "HOLD")
                self.assertGreater(result["content_reads"], 0)
                self.assertFalse(result["scanner_called"])

    def test_screening_seam_receives_only_exact_captured_approved_bytes(self):
        files = {"README.md": b"Invented portable documentation.\n", "src/example.py": INVENTED}
        with fixture(files=files) as case:
            scanner, terms = case.metadata / "scanner.py", case.metadata / "terms.json"
            write_private(scanner, b"# Invented nonexecuted scanner placeholder for pure seam.\n")
            write_private(terms, b"[]\n")
            before = inventory_bytes(case.root)
            def screen(scanner_path, terms_path, proposal, captured, **kwargs):
                self.assertLessEqual(set(kwargs), {"forbidden_ids"})
                self.assertEqual((scanner_path, terms_path), (scanner, terms))
                self.assertEqual(proposal, case.proposal)
                self.assertEqual(captured, files)
                self.assertTrue(all(type(raw) is bytes for raw in captured.values()))
                return {"findings": [], "control_pins": synthetic_screen_pins(scanner, terms)}
            with patch.object(gate, "_screen_snapshot", side_effect=screen) as called:
                result = self.assess(case, scanner_path=scanner, private_terms_path=terms)
            called.assert_called_once()
            self.assertEqual((result["eligibility"], result["text_review"]), ("ELIGIBLE_FOR_TEXT_REVIEW", "PASS"))
            self.assertTrue(result["scanner_called"])
            self.assertEqual(result["content_reads"], 2)
            self.assertEqual(inventory_bytes(case.root), before)

    def test_requested_screening_does_not_override_artifact_or_confidentiality_holds(self):
        for change in ("artifact", "confidentiality"):
            with self.subTest(change=change), fixture(synthetic=True) as case:
                if change == "artifact":
                    case.proposal["files"][0]["artifact_kind"] = case.review["files"][0]["artifact_kind"] = "runtime_record"
                    save_proposal(case)
                else:
                    case.review["files"][0]["confidentiality"] = "unknown"
                    save_review(case)
                scanner, terms = case.metadata / "scanner.py", case.metadata / "terms.json"
                write_private(scanner, b"# Invented unexecuted placeholder.\n"); write_private(terms, b"[]\n")
                with patch.object(gate, "_screen_snapshot", side_effect=AssertionError("screening bypassed HOLD")) as screen, \
                        patch.object(gate, "_read_member", side_effect=AssertionError("content read before HOLD")) as reads:
                    result = self.assess(case, scanner_path=scanner, private_terms_path=terms)
                self.assertEqual(result["eligibility"], "HOLD")
                self.assertEqual(result["content_reads"], 0)
                self.assertFalse(result["scanner_called"])
                reads.assert_not_called(); screen.assert_not_called()

    def test_screen_review_retains_finding_and_never_becomes_publication_permission(self):
        with fixture() as case:
            scanner, terms = case.metadata / "scanner.py", case.metadata / "terms.json"
            write_private(scanner, b"# Invented nonexecuted placeholder.\n"); write_private(terms, b"[]\n")
            findings = [{"path": "src/example.py", "check": "PRIVATE_TERM"}]
            with patch.object(gate, "_screen_snapshot", return_value={"findings": findings, "control_pins": synthetic_screen_pins(scanner, terms)}):
                result = self.assess(case, scanner_path=scanner, private_terms_path=terms)
            self.assertTrue(result["scanner_called"])
            self.assertEqual(result["text_review"], "REVIEW")
            self.assertEqual(result["findings"], findings)
            self.assertFalse(result["publication_authorized"])

    def test_read_failure_reason_never_copies_exception_text_or_private_paths(self):
        with fixture() as case:
            marker = "INVENTED-private-error-marker-913"
            with patch.object(gate, "_read_member", side_effect=OSError(marker + str(case.candidate))):
                result = self.assess(case)
            self.assertEqual(result["eligibility"], "HOLD")
            self.assertNotIn(marker, json.dumps(result))
            self.assertNotIn(str(case.root), json.dumps(result))
            self.assertFalse(result["scanner_called"])

    def test_cli_completion_is_written_last_and_partial_write_failures_preserve_unqualified_evidence(self):
        # Faults are injected before the named write, not simulated OS crashes.
        for fault in (None, "REVIEW.txt", "result.json", "COMPLETE.json"):
            with self.subTest(fault=fault), fixture() as case:
                receipt = case.root / "receipt"
                before_candidate = inventory_bytes(case.candidate)
                before_metadata = inventory_bytes(case.metadata)
                original = gate._write_new
                attempted = []
                marker = "INVENTED-private-write-error-629"
                def write(fd, name, raw):
                    attempted.append(name)
                    if name == fault:
                        raise OSError(marker + str(case.root))
                    return original(fd, name, raw)
                output = StringIO()
                previous_umask = os.umask(0o077)
                try:
                    with patch.object(gate, "_write_new", side_effect=write), redirect_stdout(output):
                        code = gate.main(["--candidate", str(case.candidate), "--proposal", str(case.proposal_path),
                                          "--review", str(case.review_path), "--receipt", str(receipt), "--eligibility-only"])
                finally:
                    os.umask(previous_umask)
                stdout = output.getvalue()
                self.assertEqual(len(stdout.splitlines()), 1)
                summary = json.loads(stdout)
                self.assertNotIn("findings", summary)
                self.assertNotIn("bindings", summary)
                self.assertNotIn(str(case.root), stdout)
                self.assertNotIn(marker, stdout)
                self.assertNotIn(INVENTED.decode().strip(), stdout)
                self.assertIs(summary["publication_authorized"], False)
                self.assertIs(summary["export_performed"], False)
                self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o700)
                self.assertEqual(inventory_bytes(case.candidate), before_candidate)
                self.assertEqual(inventory_bytes(case.metadata), before_metadata)
                expected_order = ["CLAIM.json", "REVIEW.md", "REVIEW.txt", "result.json", "COMPLETE.json"]
                if fault is None:
                    self.assertEqual(code, 0)
                    self.assertEqual(attempted, expected_order)
                    self.assertEqual({path.name for path in receipt.iterdir()}, set(expected_order))
                    self.assertEqual(summary["eligibility"], "ELIGIBLE_FOR_TEXT_REVIEW")
                    private = json.loads((receipt / "result.json").read_bytes())
                    self.assertEqual(set(private), FIELDS)
                    self.assertEqual(private["eligibility"], "ELIGIBLE_FOR_TEXT_REVIEW")
                    completion = json.loads((receipt / "COMPLETE.json").read_bytes())
                    self.assertEqual(completion, {"format": "outlands-source-export-complete-v1", "files": {
                        name: digest((receipt / name).read_bytes()) for name in expected_order[:-1]}})
                else:
                    self.assertEqual(code, 2)
                    self.assertEqual(summary["eligibility"], "REFUSED")
                    self.assertEqual(attempted, expected_order[:expected_order.index(fault) + 1])
                    self.assertEqual({path.name for path in receipt.iterdir()}, set(expected_order[:expected_order.index(fault)]))
                    self.assertEqual((receipt / "result.json").exists(), fault == "COMPLETE.json")
                    self.assertFalse((receipt / "COMPLETE.json").exists())
                    self.assertTrue((receipt / "CLAIM.json").is_file())
                    self.assertTrue((receipt / "REVIEW.md").is_file())
                for path in receipt.iterdir():
                    info = path.lstat()
                    self.assertTrue(stat.S_ISREG(info.st_mode))
                    self.assertEqual((stat.S_IMODE(info.st_mode), info.st_uid, info.st_nlink), (0o600, os.getuid(), 1))
                if (receipt / "REVIEW.txt").exists():
                    self.assertEqual((receipt / "REVIEW.md").read_bytes(), (receipt / "REVIEW.txt").read_bytes())


if __name__ == "__main__":
    unittest.main()
