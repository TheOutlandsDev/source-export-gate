"""Invented selected-only intake regressions, including retained write faults.

No generated draft is approved. Faults are synchronous Python injections, not
native crash, fsync durability or hostile-concurrent-owner qualification.
"""

from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import patch

import build_review_intake as builder
from test_build_review_intake_cli import (DEFAULT_FILES, FAMILIES, OUTPUT_ORDER,
    PENDING_FIELDS, PROOF_FIELDS, RESULT_FIELDS, canonical, complete_value, digest,
    intake_fixture, pending_proof, snapshot, write_private)
from test_large_candidate_cli import sized_files


class BuildReviewIntakeTests(unittest.TestCase):
    def setUp(self):
        self.guards = ExitStack()
        self.addCleanup(self.guards.close)
        self.denied = [self.guards.enter_context(patch(target, side_effect=AssertionError("external operation forbidden")))
            for target in ("socket.socket", "socket.create_connection", "subprocess.Popen", "subprocess.run",
                           "os.execve", "os.system", "os.posix_spawn", "os.posix_spawnp", "os.fork")]

    def tearDown(self):
        for denied in self.denied:
            denied.assert_not_called()

    def validate(self, result):
        self.assertEqual(set(result), RESULT_FIELDS)
        self.assertEqual(result["format"], "outlands-private-review-intake-result-v1")
        self.assertIn(result["status"], {"HOLD", "REFUSED", "UNVERIFIABLE"})
        self.assertEqual(result["publication_status"], "HELD")
        for key in ("publication_authorized", "export_performed", "destination_verified", "git_metadata_reviewed", "scanner_called"):
            self.assertIs(result[key], False)
        for key in ("declared_files", "content_reads"):
            self.assertIs(type(result[key]), int)
            self.assertGreaterEqual(result[key], 0)
            self.assertLessEqual(result[key], 128)
        self.assertIs(type(result["recheck_reads"]), int)
        self.assertGreaterEqual(result["recheck_reads"], 0)
        self.assertLessEqual(result["recheck_reads"], 256)
        self.assertIs(type(result["draft_created"]), bool)
        self.assertIs(type(result["complete_written"]), bool)
        self.assertEqual(result["files_written"], list(OUTPUT_ORDER[:len(result["files_written"])]))
        self.assertIs(type(result["reason_codes"]), list)
        for code in result["reason_codes"]:
            self.assertIs(type(code), str)
            self.assertRegex(code, r"^[A-Z][A-Z0-9_]{0,63}$")
        self.assertNotIn("INVENTED_DO_NOT_ECHO", json.dumps(result))
        if result["status"] != "HOLD":
            self.assertIsNone(result["bindings"])

    def call(self, case, status="HOLD", *, zero=False, output=None, permitted_changes=()):
        before = snapshot(case.root)
        seen = []
        original = builder.gate._read_member
        original_scandir, forbidden_enumerations = os.scandir, []
        def enumerate_output_only(target):
            # The newly-created packet may be checked for exact membership.
            # Every attempt to enumerate the candidate or existing directories
            # remains an explicit failure even if the builder catches it.
            if "intake" not in before and case.output.exists():
                info = case.output.lstat()
                observed = os.fstat(target) if type(target) is int else Path(target).lstat()
                if (info.st_dev, info.st_ino) == (observed.st_dev, observed.st_ino):
                    return original_scandir(target)
            forbidden_enumerations.append(True)
            raise AssertionError("intake enumerated outside its new output")
        def read(*args, **kwargs):
            raw = original(*args, **kwargs)
            seen.append((args[1], len(raw)))
            return raw
        with ExitStack() as stack:
            assessed = stack.enter_context(patch.object(builder.gate, "assess", side_effect=AssertionError("intake assessed")))
            screened = stack.enter_context(patch.object(builder.gate, "_screen_snapshot", side_effect=AssertionError("intake screened")))
            inventoried = stack.enter_context(patch.object(builder.gate, "_inventory", side_effect=AssertionError("intake inventoried candidate")))
            stack.enter_context(patch("os.scandir", side_effect=enumerate_output_only))
            member = stack.enter_context(patch.object(builder.gate, "_read_member",
                side_effect=AssertionError("invalid intake read selected content") if zero else read))
            result = builder.build_intake(case.candidate, case.selection, case.output if output is None else output)
        for forbidden in (assessed, screened, inventoried):
            forbidden.assert_not_called()
        self.assertEqual(forbidden_enumerations, [])
        self.assertEqual(result["content_reads"] + result["recheck_reads"], member.call_count)
        if zero:
            member.assert_not_called()
            self.assertEqual(result["content_reads"], 0)
            self.assertEqual(result["recheck_reads"], 0)
        self.validate(result)
        self.assertEqual(result["status"], status)
        self.assertNotIn(str(case.root), json.dumps(result))
        selected = {row["path"] for row in case.selection_doc["files"]}
        self.assertTrue(all(name in selected for name, length in seen))
        after = snapshot(case.root)
        excluded = {str(path.relative_to(case.root)) for path in permitted_changes}
        for name, row in before.items():
            if name not in excluded:
                self.assertEqual(after[name][:4] if name == "." else after[name], row[:4] if name == "." else row)
        new = set(after) - set(before)
        self.assertTrue(all(name == "intake" or name.startswith("intake/") for name in new))
        if status == "HOLD":
            self.assertEqual(new, {"intake", *("intake/" + name for name in OUTPUT_ORDER)})
            self.assertEqual(result["files_written"], list(OUTPUT_ORDER))
            self.assertEqual(result["reason_codes"], ["REVIEW_PENDING"])
            self.assertEqual(result["content_reads"], len(case.files))
            self.assertEqual(result["recheck_reads"], 2 * len(case.files))
            self.assertIs(result["draft_created"], True)
            self.assertIs(result["complete_written"], True)
        elif status == "REFUSED":
            self.assertFalse(new)
        return result, seen

    def test_mixed_unicode_pending_draft_binds_actual_bytes_and_gate_reads_zero(self):
        with intake_fixture() as case:
            result, seen = self.call(case)
            self.assertEqual(result["declared_files"], 3)
            self.assertEqual([name for name, size in seen[:3]], sorted(DEFAULT_FILES))
            binding = result["bindings"]
            self.assertEqual(json.loads((case.output / "evidence-bindings.json").read_bytes()), binding)
            self.assertEqual(set(binding), {"format", "selection_sha256", "policy", "files", "proposal_sha256", "review_draft_sha256"})
            self.assertEqual(binding["format"], "outlands-source-export-intake-bindings-v1")
            self.assertEqual(binding["selection_sha256"], digest(case.selection.read_bytes()))
            self.assertEqual(binding["policy"], {"gate_sha256": digest(Path(builder.gate.__file__).read_bytes()),
                                                 "intake_sha256": digest(Path(builder.__file__).read_bytes())})
            self.assertEqual(binding["proposal_sha256"], digest(case.proposal.read_bytes()))
            self.assertEqual(binding["review_draft_sha256"], digest(case.review.read_bytes()))
            before = snapshot(case.root)
            with ExitStack() as stack:
                member = stack.enter_context(patch.object(builder.gate, "_read_member", side_effect=AssertionError("pending draft read content")))
                inventory = stack.enter_context(patch.object(builder.gate, "_inventory", side_effect=AssertionError("pending draft inventoried")))
                screen = stack.enter_context(patch.object(builder.gate, "_screen_snapshot", side_effect=AssertionError("pending draft screened")))
                gate_result = builder.gate.assess(case.candidate, case.proposal, case.review)
            for trap in (member, inventory, screen):
                trap.assert_not_called()
            self.assertEqual(snapshot(case.root), before)
            self.assertEqual((gate_result["eligibility"], gate_result["reason_codes"], gate_result["content_reads"]),
                             ("HOLD", ["REVIEW_INCOMPLETE"], 0))
            proof = pending_proof(case, "unit-pending", result, gate_result)
            self.assertEqual(set(proof), PROOF_FIELDS)
            self.assertEqual((proof["actual_file_count"], proof["actual_total_bytes"]), (3, 136))

    def test_all_six_review_fields_remain_pending_for_each_selected_kind(self):
        files = {"NOTICE.txt": b"Invented notice.\n", "guide.md": b"Invented guide.\n", "examples/invented.json": b"Invented fixture.\n"}
        kinds = {"NOTICE.txt": "notice", "guide.md": "documentation", "examples/invented.json": "synthetic_example"}
        with intake_fixture(files=files, kinds=kinds, synthetic=True) as case:
            self.call(case)
            review = json.loads(case.review.read_bytes())
            self.assertEqual(review["publication_authorized"], False)
            self.assertTrue(all(row[key] == "pending" for row in review["files"] for key in PENDING_FIELDS))
            self.assertTrue(all(row["decision"] != "eligible" and row["notices"] != "preserved" for row in review["files"]))

    def test_selected_only_access_ignores_unselected_unsafe_entries_without_inventory(self):
        with intake_fixture() as case:
            write_private(case.candidate / "unselected.env", b"INVENTED_DO_NOT_ECHO\n")
            os.mkfifo(case.candidate / "unselected.pipe", mode=0o600)
            (case.candidate / "unselected-link").symlink_to(case.root / "absent")
            result, seen = self.call(case)
            self.assertEqual(result["content_reads"], 3)
            self.assertEqual(set(name for name, size in seen), set(case.files))
            self.assertTrue(all("unselected" not in row["path"] for row in result["bindings"]["files"]))

    def test_exact_128_selected_files_and_empty_or_129_row_refusals(self):
        for count in (0, 128, 129):
            files = {"file%03d.py" % i: b"# Invented small selected text.\n" for i in range(128)} if count == 128 else None
            with self.subTest(count=count), intake_fixture(files=files) as case:
                if count != 128:
                    case.selection_doc["files"] = [{"path": "file%03d.py" % i, "artifact_kind": "source", "synthetic_fixture": False} for i in range(count)]
                    case.save_selection()
                self.call(case, "HOLD" if count == 128 else "REFUSED", zero=count != 128)

    def test_strict_json_utf8_duplicate_keys_nonfinite_and_root_types(self):
        for raw in (b"\xff", b'{"format":"x","format":"y"}', b'{"files":NaN}', b"[]", b"null", b"42"):
            with self.subTest(raw=raw), intake_fixture() as case:
                write_private(case.selection, raw, replace=True)
                self.call(case, "REFUSED", zero=True)

    def test_selection_exact_fields_and_nonboolean_declarations(self):
        for change in ("extra", "format", "family-type", "files-type", "row-extra", "kind-type", "synthetic-type"):
            with self.subTest(change=change), intake_fixture() as case:
                doc = case.selection_doc
                if change == "extra": doc["private_note"] = "INVENTED_DO_NOT_ECHO"
                elif change == "format": doc["format"] = "outlands-source-export-proposal-v1"
                elif change == "family-type": doc["family"] = []
                elif change == "files-type": doc["files"] = {}
                elif change == "row-extra": doc["files"][0]["sha256"] = "0" * 64
                elif change == "kind-type": doc["files"][0]["artifact_kind"] = None
                else: doc["files"][0]["synthetic_fixture"] = 1
                case.save_selection()
                self.call(case, "REFUSED", zero=True)

    def test_paths_order_duplicates_absolute_traversal_and_depth_are_strict(self):
        for change in ("unsorted", "duplicate", "absolute", "traversal", "backslash", "depth", "empty"):
            with self.subTest(change=change), intake_fixture() as case:
                rows = case.selection_doc["files"]
                if change == "unsorted": rows.reverse()
                elif change == "duplicate": rows.append(dict(rows[-1]))
                else:
                    rows[0]["path"] = {"absolute": "/invented/private/file.py", "traversal": "../file.py",
                        "backslash": "folder\\file.py", "depth": "/".join(["a"] * 8 + ["file.py"]), "empty": ""}[change]
                    rows.sort(key=lambda row: row["path"])
                case.save_selection()
                self.call(case, "REFUSED", zero=True)
        deepest = "/".join(["a"] * 7 + ["file.py"])
        with intake_fixture(files={deepest: b"# Invented depth-eight text.\n"}) as case:
            self.call(case)

    def test_ineligible_paths_classes_and_false_synthetic_examples_are_not_intaken(self):
        for change in ("path", "kind", "synthetic", "unknown-kind", "family"):
            with self.subTest(change=change), intake_fixture() as case:
                row = case.selection_doc["files"][0]
                if change == "path": row["path"] = "private.env"
                elif change == "kind": row["artifact_kind"] = "runtime_record"
                elif change == "synthetic": row.update(artifact_kind="synthetic_example", synthetic_fixture=False)
                elif change == "unknown-kind": row["artifact_kind"] = "invented-kind"
                else: case.selection_doc["family"] = "invented-unknown"
                case.selection_doc["files"].sort(key=lambda value: value["path"])
                case.save_selection()
                self.call(case, "REFUSED", zero=True)

    def test_all_known_families_are_copied_as_explicit_declarations(self):
        for family in FAMILIES:
            with self.subTest(family=family), intake_fixture(family=family) as case:
                result, _ = self.call(case)
                self.assertEqual(json.loads(case.proposal.read_bytes())["family"], family)
                self.assertEqual(json.loads(case.review.read_bytes())["family"], family)
                self.assertTrue(all(row["artifact_kind"] in {"source", "documentation"} for row in result["bindings"]["files"]))

    def test_missing_selected_file_directory_and_nonprivate_modes_refuse_before_reads(self):
        for change in ("missing", "directory", "file-mode", "parent-mode", "root-mode"):
            with self.subTest(change=change), intake_fixture() as case:
                member = case.candidate / case.selection_doc["files"][0]["path"]
                if change == "missing": member.unlink()
                elif change == "directory":
                    member.unlink()
                    member.mkdir(mode=0o700)
                elif change == "file-mode": member.chmod(0o644)
                elif change == "parent-mode": member.parent.chmod(0o755)
                else: case.candidate.chmod(0o755)
                self.call(case, "REFUSED", zero=True)

    def test_selected_member_root_and_parent_links_and_hardlinks_refuse(self):
        for change in ("file-link", "hardlink", "parent-link", "root-link"):
            with self.subTest(change=change), intake_fixture() as case:
                member = case.candidate / case.selection_doc["files"][0]["path"]
                if change in {"file-link", "hardlink"}:
                    outside = case.root / "invented-member.txt"
                    write_private(outside, member.read_bytes())
                    member.unlink()
                    if change == "file-link": member.symlink_to(outside)
                    else: os.link(outside, member)
                elif change == "parent-link":
                    original = case.root / "original-docs"
                    member.parent.rename(original)
                    member.parent.symlink_to(original, target_is_directory=True)
                else:
                    original = case.root / "original-candidate"
                    case.candidate.rename(original)
                    case.candidate.symlink_to(original, target_is_directory=True)
                self.call(case, "REFUSED", zero=True)

    def test_selection_modes_links_and_hardlinks_are_not_adopted(self):
        for change in ("mode", "link", "hardlink"):
            with self.subTest(change=change), intake_fixture() as case:
                if change == "mode": case.selection.chmod(0o644)
                else:
                    outside = case.root / "invented-selection.json"
                    write_private(outside, case.selection.read_bytes())
                    case.selection.unlink()
                    if change == "link": case.selection.symlink_to(outside)
                    else: os.link(outside, case.selection)
                self.call(case, "REFUSED", zero=True)

    def test_selection_inside_candidate_and_fixed_code_location_refuse_before_policy_read(self):
        with intake_fixture() as case:
            inside = case.candidate / "selection.json"
            write_private(inside, case.selection.read_bytes())
            case.selection = inside
            self.call(case, "REFUSED", zero=True)
        for target in ("builder", "gate"):
            with self.subTest(target=target), intake_fixture() as case:
                module = builder if target == "builder" else builder.gate
                with patch.object(module, "__file__", str(case.candidate / "invented.py")), \
                     patch.object(builder, "_policy_snapshot", side_effect=AssertionError("invalid location read code")) as policy:
                    self.call(case, "REFUSED", zero=True)
                policy.assert_not_called()

    def test_existing_dangling_unsafe_and_overlapping_output_paths_refuse(self):
        for change in ("directory", "file", "dangling", "candidate", "ancestor", "selection", "parent-mode"):
            with self.subTest(change=change), intake_fixture() as case:
                target = case.output
                if change == "directory": target.mkdir(mode=0o700)
                elif change == "file": write_private(target, b"invented existing\n")
                elif change == "dangling": target.symlink_to(case.root / "absent")
                elif change == "candidate": target = case.candidate / "intake"
                elif change == "ancestor": target = case.root
                elif change == "selection": target = case.selection
                else:
                    parent = case.root / "public-parent"
                    parent.mkdir(mode=0o700)
                    parent.chmod(0o755)
                    target = parent / "intake"
                self.call(case, "REFUSED", zero=True, output=target)

    def test_raw_selection_size_limit_refuses_without_member_reads(self):
        with intake_fixture() as case:
            write_private(case.selection, b" " * 262145, replace=True)
            self.call(case, "REFUSED", zero=True)

    def test_invalid_utf8_and_nul_selected_text_leave_no_output(self):
        for raw in (b"\xff", b"# invented\x00text\n"):
            with self.subTest(raw=raw), intake_fixture(files={"x.py": raw}) as case:
                result, _ = self.call(case, "REFUSED")
                self.assertEqual((result["content_reads"], result["reason_codes"]), (1, ["TEXT_ONLY"]))

    def test_member_changed_before_original_reader_is_a_refusal_with_attempt_retained(self):
        with intake_fixture() as case:
            name = case.selection_doc["files"][0]["path"]
            member = case.candidate / name
            original, changed = builder.gate._read_member, []
            def drift(*args, **kwargs):
                if not changed:
                    changed.append(True)
                    write_private(member, member.read_bytes() + b"x", replace=True)
                return original(*args, **kwargs)
            with patch.object(builder.gate, "_read_member", side_effect=drift):
                result, _ = self.call(case, "REFUSED", permitted_changes=(member,))
            self.assertEqual(result["content_reads"], 1)

    def test_selection_changed_after_initial_capture_refuses_before_output(self):
        with intake_fixture() as case:
            original, changed = builder.gate._read_member, []
            def drift(*args, **kwargs):
                raw = original(*args, **kwargs)
                if not changed:
                    changed.append(True)
                    write_private(case.selection, case.selection.read_bytes() + b" ", replace=True)
                return raw
            with patch.object(builder.gate, "_read_member", side_effect=drift):
                result, _ = self.call(case, "REFUSED", permitted_changes=(case.selection,))
            self.assertEqual(result["content_reads"], 3)

    def test_same_size_member_changed_after_initial_capture_refuses_before_output(self):
        with intake_fixture() as case:
            name = case.selection_doc["files"][0]["path"]
            member = case.candidate / name
            original, changed = builder.gate._read_member, []
            def drift(*args, **kwargs):
                raw = original(*args, **kwargs)
                if not changed:
                    changed.append(True)
                    altered = raw.replace(b"Invented", b"Modified", 1)
                    self.assertEqual(len(altered), len(raw))
                    write_private(member, altered, replace=True)
                return raw
            with patch.object(builder.gate, "_read_member", side_effect=drift):
                result, _ = self.call(case, "REFUSED", permitted_changes=(member,))
            self.assertEqual(result["content_reads"], 3)

    def test_oserror_before_each_write_retains_only_successful_prefix(self):
        for stop_name in OUTPUT_ORDER:
            with self.subTest(stop_name=stop_name), intake_fixture() as case:
                original, calls = builder._write_new, []
                def fail(fd, name, raw):
                    calls.append(name)
                    if name == stop_name:
                        raise OSError("INVENTED_DO_NOT_ECHO")
                    return original(fd, name, raw)
                with patch.object(builder, "_write_new", side_effect=fail):
                    result, _ = self.call(case, "UNVERIFIABLE")
                prefix = list(OUTPUT_ORDER[:OUTPUT_ORDER.index(stop_name)])
                self.assertEqual(calls, prefix + [stop_name])
                self.assertEqual(result["files_written"], prefix)
                self.assertEqual({path.name for path in case.output.iterdir()}, set(prefix))
                self.assertEqual(result["content_reads"], 3)
                self.assertFalse(result["complete_written"])
                self.assertEqual(result["draft_created"], "review-draft.json" in prefix)

    def test_half_written_proposal_is_retained_unverifiable_without_repair(self):
        with intake_fixture() as case:
            original = builder._write_new
            def half(fd, name, raw):
                if name == "proposal.json":
                    original(fd, name, raw[:len(raw) // 2])
                    raise OSError("controlled half-buffer failure")
                return original(fd, name, raw)
            with patch.object(builder, "_write_new", side_effect=half):
                result, _ = self.call(case, "UNVERIFIABLE")
            self.assertEqual(result["files_written"], ["CLAIM.json"])
            self.assertEqual({path.name for path in case.output.iterdir()}, {"CLAIM.json", "proposal.json"})
            self.assertGreater(case.proposal.stat().st_size, 0)
            self.assertFalse((case.output / "INTAKE-COMPLETE.json").exists())

    def test_half_written_evidence_retained_without_completion_or_retry(self):
        with intake_fixture() as case:
            original = builder._write_new
            def half(fd, name, raw):
                if name == "evidence-bindings.json":
                    original(fd, name, raw[:len(raw) // 2])
                    raise OSError("controlled partial evidence write")
                return original(fd, name, raw)
            with patch.object(builder, "_write_new", side_effect=half):
                result, _ = self.call(case, "UNVERIFIABLE")
            self.assertEqual(result["files_written"], list(OUTPUT_ORDER[:5]))
            self.assertEqual({p.name for p in case.output.iterdir()}, set(OUTPUT_ORDER[:6]))
            self.assertGreater((case.output / "evidence-bindings.json").stat().st_size, 0)
            self.assertFalse(result["complete_written"])
            self.assertIsNone(result["bindings"])
            self.assertFalse((case.output / "INTAKE-COMPLETE.json").exists())

    def test_keyboardinterrupt_retains_pending_prefix_and_closes_owned_fds(self):
        with intake_fixture() as case:
            before, fds = snapshot(case.root), []
            original = builder._write_new
            def interrupt(fd, name, raw):
                fds.append(fd)
                if name == "CHECKLIST.md":
                    raise KeyboardInterrupt("controlled injected interruption")
                return original(fd, name, raw)
            with patch.object(builder, "_write_new", side_effect=interrupt):
                with self.assertRaises(KeyboardInterrupt):
                    builder.build_intake(case.candidate, case.selection, case.output)
            for fd in set(fds):
                with self.assertRaises(OSError) as failure:
                    os.fstat(fd)
                self.assertEqual(failure.exception.errno, errno.EBADF)
            self.assertEqual({path.name for path in case.output.iterdir()}, set(OUTPUT_ORDER[:3]))
            self.assertTrue(all(row[key] == "pending" for row in json.loads(case.review.read_bytes())["files"] for key in PENDING_FIELDS))
            after = snapshot(case.root)
            for name, row in before.items():
                self.assertEqual(after[name][:4] if name == "." else after[name], row[:4] if name == "." else row)

    def test_late_write_selection_or_member_drift_keeps_uncompleted_pending_output(self):
        for target in ("selection", "member"):
            with self.subTest(target=target), intake_fixture() as case:
                member = case.candidate / case.selection_doc["files"][0]["path"]
                path = case.selection if target == "selection" else member
                original = builder._write_new
                def drift(fd, name, raw):
                    original(fd, name, raw)
                    if name == "review-draft.json":
                        old = path.read_bytes()
                        changed = old + b" " if target == "selection" else old.replace(b"Invented", b"Modified", 1)
                        write_private(path, changed, replace=True)
                with patch.object(builder, "_write_new", side_effect=drift):
                    result, _ = self.call(case, "UNVERIFIABLE", permitted_changes=(path,))
                self.assertEqual(result["files_written"], list(OUTPUT_ORDER[:-1]))
                self.assertTrue(result["draft_created"])
                self.assertFalse((case.output / "INTAKE-COMPLETE.json").exists())

    def test_code_pin_drift_before_create_or_before_marker_never_completes(self):
        for change_call in (2, 3):
            with self.subTest(change_call=change_call), intake_fixture() as case:
                original, calls = builder._policy_snapshot, []
                def drift(*args, **kwargs):
                    value = original(*args, **kwargs)
                    calls.append(True)
                    if len(calls) == change_call:
                        pin, raw_hash = value["intake"]
                        value["intake"] = (pin, "0" * 64 if raw_hash != "0" * 64 else "1" * 64)
                    return value
                with patch.object(builder, "_policy_snapshot", side_effect=drift):
                    result, _ = self.call(case, "REFUSED" if change_call == 2 else "UNVERIFIABLE")
                self.assertEqual(result["reason_codes"], ["POLICY_CHANGED"])
                self.assertFalse((case.output / "INTAKE-COMPLETE.json").exists())

    def test_late_written_metadata_tamper_or_extra_file_never_gets_a_marker(self):
        for change in ("proposal", "extra"):
            with self.subTest(change=change), intake_fixture() as case:
                original = builder._write_new
                def tamper(fd, name, raw):
                    original(fd, name, raw)
                    if name == "CHECKLIST.txt":
                        if change == "proposal":
                            write_private(case.proposal, case.proposal.read_bytes() + b" ", replace=True)
                        else:
                            write_private(case.output / "unexpected.json", b"{}\n")
                with patch.object(builder, "_write_new", side_effect=tamper):
                    result, _ = self.call(case, "UNVERIFIABLE")
                self.assertEqual(result["files_written"], list(OUTPUT_ORDER[:-1]))
                self.assertFalse((case.output / "INTAKE-COMPLETE.json").exists())

    def test_fsync_error_is_retained_uncertainty_not_a_completed_draft(self):
        with intake_fixture() as case:
            with patch.object(builder.os, "fsync", side_effect=OSError("controlled fsync refusal")):
                result, _ = self.call(case, "UNVERIFIABLE")
            self.assertEqual(result["files_written"], [])
            self.assertEqual({path.name for path in case.output.iterdir()}, {"CLAIM.json"})
            self.assertFalse((case.output / "INTAKE-COMPLETE.json").exists())

    def test_unexpected_reader_exception_is_sanitized_and_has_no_output(self):
        with intake_fixture() as case:
            with patch.object(builder.gate, "_read_member", side_effect=RuntimeError("INVENTED_DO_NOT_ECHO /invented/private")):
                result, _ = self.call(case, "REFUSED")
            self.assertEqual((result["reason_codes"], result["content_reads"]), (["INTERNAL_REFUSAL"], 1))

    def test_completed_output_is_not_overwritten_or_reinterpreted(self):
        with intake_fixture() as case:
            self.call(case)
            before = snapshot(case.output)
            result, _ = self.call(case, "REFUSED", zero=True)
            self.assertEqual(snapshot(case.output), before)
            self.assertEqual(result["reason_codes"], ["OUTPUT_EXISTS"])

    def test_output_contains_metadata_only_and_paired_private_fixed_checklists(self):
        files = {"private_note.py": b"# INVENTED_DO_NOT_ECHO payload only, never copied.\n"}
        with intake_fixture(files=files) as case:
            self.call(case)
            self.assertEqual(stat.S_IMODE(case.output.stat().st_mode), 0o700)
            for path in case.output.iterdir():
                info = path.lstat()
                self.assertTrue(stat.S_ISREG(info.st_mode))
                self.assertEqual((stat.S_IMODE(info.st_mode), info.st_uid, info.st_nlink), (0o600, os.getuid(), 1))
                raw = path.read_bytes()
                self.assertNotIn(files["private_note.py"], raw)
                self.assertNotIn(str(case.root).encode(), raw)
                self.assertNotIn(b"INVENTED_DO_NOT_ECHO", raw)
            note = (case.output / "CHECKLIST.md").read_bytes()
            self.assertEqual(note, (case.output / "CHECKLIST.txt").read_bytes())
            self.assertIn(b"pending", note)
            self.assertNotIn(b"\x00", note)
            note.decode("utf-8")


if __name__ == "__main__":
    unittest.main()
