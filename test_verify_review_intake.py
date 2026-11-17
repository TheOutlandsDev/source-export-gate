"""Fresh invented Python/Java fixtures; no real project or held task."""
from contextlib import ExitStack, redirect_stdout
from io import StringIO
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import verify_review_intake as v

FILES = {"Example.java": "// Invented Java café.\n".encode(), "example.py": "# Invented Python π.\n".encode()}


def write(p, raw):
    if p.exists():
        p.write_bytes(raw)
    else:
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)


def encoded(x):
    return (json.dumps(x, sort_keys=True) + "\n").encode()


def snapshot(root):
    rows = {}
    for p in [root, *sorted(root.rglob("*"))]:
        t = p.lstat()
        rows[str(p.relative_to(root))] = (t.st_mode, t.st_ino, t.st_size, t.st_mtime_ns, t.st_ctime_ns,
            hashlib.sha256(p.read_bytes()).hexdigest() if stat.S_ISREG(t.st_mode) else None)
    return rows


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="invented-intake-verify-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.candidate = self.root / "candidate"
        self.candidate.mkdir(mode=0o700)
        for name, raw in FILES.items(): write(self.candidate / name, raw)
        self.selection = self.root / "selection.json"
        self.doc = {"format":"outlands-source-export-intake-selection-v1", "family":"java-python-kits", "files":[
            {"path":n,"artifact_kind":"source","synthetic_fixture":True} for n in sorted(FILES)]}
        write(self.selection, encoded(self.doc))
        self.intake = self.root / "intake"
        result = v.builder.build_intake(self.candidate, self.selection, self.intake)
        self.assertEqual(result["status"], "HOLD")

    def call(self, status="CONSISTENT", reads=None, *, require_bindings=False, no_candidate_open=False):
        before = snapshot(self.root)
        original_open = os.open
        def readonly(path, flags, *a, **kw):
            if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                raise AssertionError("verifier attempted write")
            return original_open(path, flags, *a, **kw)
        opened_candidates = []
        original_dir = v.gate._open_dir
        def observed_dir(path):
            if Path(path) == self.candidate:
                opened_candidates.append(path)
                if no_candidate_open:
                    raise AssertionError("candidate opened before binding validation")
            return original_dir(path)
        with ExitStack() as stack:
            stack.enter_context(patch.object(v.gate, "_open_dir", side_effect=observed_dir))
            traps = [stack.enter_context(patch(target, side_effect=AssertionError("forbidden operation"))) for target in
                ("socket.socket", "socket.create_connection", "subprocess.Popen", "subprocess.run", "os.system", "os.fork", "os.kill", "os.killpg")]
            for name in ("assess", "_inventory", "_screen_snapshot"):
                traps.append(stack.enter_context(patch.object(v.gate, name, side_effect=AssertionError("forbidden assessment"))))
            stack.enter_context(patch("os.open", side_effect=readonly))
            member = stack.enter_context(patch.object(v.gate, "_read_member", wraps=v.gate._read_member))
            result = v.verify_intake(self.candidate, self.selection, self.intake, require_bindings=require_bindings)
        if no_candidate_open: self.assertEqual(opened_candidates, [])
        for trap in traps: trap.assert_not_called()
        self.assertEqual(snapshot(self.root), before)
        self.assertEqual(result["status"], status)
        self.assertEqual(result["content_reads"], member.call_count)
        if reads is not None: self.assertEqual(result["content_reads"], reads)
        self.assertEqual(result["eligibility"], "HOLD")
        self.assertEqual(result["review_status"], "PENDING")
        for key in ("publication_authorized", "export_performed", "destination_verified", "git_metadata_reviewed", "scanner_called"):
            self.assertIs(result[key], False)
        self.assertNotIn(str(self.root), json.dumps(result))
        return result

    def rebind(self, name, doc):
        write(self.intake / name, encoded(doc))
        marker = json.loads((self.intake / "INTAKE-COMPLETE.json").read_bytes())
        marker["files"][name] = hashlib.sha256((self.intake / name).read_bytes()).hexdigest()
        write(self.intake / "INTAKE-COMPLETE.json", encoded(marker))

    def test_consistent_unicode_and_pending(self): self.call(reads=2)
    def test_missing_each_packet_member_zero_reads(self):
        for name in v.builder.OUTPUT_FILES:
            with self.subTest(name=name):
                p=self.intake/name; raw=p.read_bytes(); p.unlink()
                self.call("DAMAGED",0); write(p,raw)
    def test_changed_each_packet_member_zero_reads(self):
        for name in v.builder.OUTPUT_FILES:
            with self.subTest(name=name):
                p=self.intake/name; raw=p.read_bytes(); write(p,raw+b"!")
                self.call("DAMAGED",0); write(p,raw)
    def test_extra_packet_member_zero_reads(self):
        write(self.intake/"extra.json",b"{}"); self.call("DAMAGED",0)
    def test_marker_malformed_duplicate_nonfinite(self):
        for raw in (b"{",b'{"format":1,"format":2}',b'{"x":NaN}',b"[]",b"\xff"):
            write(self.intake/"INTAKE-COMPLETE.json",raw);self.call("DAMAGED",0)
    def test_coherent_review_promotion_refused(self):
        review=json.loads((self.intake/"review-draft.json").read_bytes())
        review["files"][0]["decision"]="eligible"
        self.rebind("review-draft.json",review);self.call("DAMAGED",0)
    def test_broken_proposal_review_binding(self):
        review=json.loads((self.intake/"review-draft.json").read_bytes());review["proposal_sha256"]="0"*64
        self.rebind("review-draft.json",review);self.call("DAMAGED",0)
    def test_packet_symlink_zero_reads(self):
        p=self.intake/"proposal.json";p.unlink();p.symlink_to(self.selection);self.call("DAMAGED",0)
    def test_packet_hardlink_zero_reads(self):
        os.link(self.intake/"proposal.json",self.root/"alias");self.call("DAMAGED",0)
    def test_packet_bad_mode_zero_reads(self):
        (self.intake/"proposal.json").chmod(0o644);self.call("DAMAGED",0)
    def test_selected_size_changed_before_content(self):
        write(self.candidate/"example.py",b"changed");self.call("STALE",0)
    def test_selected_same_size_hash_changed(self):
        p=self.candidate/"Example.java";raw=p.read_bytes();write(p,b"!"+raw[1:]);self.call("STALE",1)
    def test_selected_missing(self):
        (self.candidate/"example.py").unlink();self.call("STALE",0)
    def test_selected_symlink(self):
        p=self.candidate/"example.py";p.unlink();p.symlink_to(self.selection);self.call("STALE",0)
    def test_selected_mode(self):
        (self.candidate/"example.py").chmod(0o644);self.call("STALE",0)
    def test_selection_changed_set_before_content(self):
        self.doc["files"].pop();write(self.selection,encoded(self.doc));self.call("STALE",0)
    def test_selection_traversal_before_content(self):
        self.doc["files"][0]["path"]="../escape.py";write(self.selection,encoded(self.doc));self.call("STALE",0)
    def test_semantically_identical_selection_whitespace(self):
        write(self.selection,self.selection.read_bytes()+b" ");self.call("STALE",0, no_candidate_open=True)
    def test_unselected_contents_not_read(self):
        write(self.candidate/"unselected.env",b"INVENTED_SECRET_SENTINEL")
        original=v.gate._read_member;seen=[]
        def member(*args,**kw):seen.append(args[1]);return original(*args,**kw)
        with patch.object(v.gate,"_read_member",side_effect=member):self.call(reads=2)
        self.assertEqual(seen,sorted(FILES))
    def test_bad_packet_before_nonexistent_candidate(self):
        self.candidate=self.root/"absent";(self.intake/"CLAIM.json").unlink();self.call("DAMAGED",0)
    def test_late_packet_mutation_detected(self):
        original=v.gate._read_member
        def member(*args,**kw):
            raw=original(*args,**kw);write(self.intake/"CHECKLIST.txt",b"changed");return raw
        with patch.object(v.gate,"_read_member",side_effect=member):
            result=v.verify_intake(self.candidate,self.selection,self.intake)
        self.assertEqual((result["status"],result["content_reads"],result["eligibility"]),("DAMAGED",2,"HOLD"))
    def test_cli_consistent_and_bad_arguments(self):
        script=Path(v.__file__)
        for args,code in [(["--candidate",str(self.candidate),"--selection",str(self.selection),"--intake",str(self.intake)],1),(["--unknown"],2)]:
            completed=subprocess.run([sys.executable,"-I","-B",str(script),*args],capture_output=True,check=False,timeout=20,cwd=self.root,
                env={"PATH":"/usr/bin:/bin","LANG":"C.UTF-8","PYTHONNOUSERSITE":"1"})
            self.assertEqual(completed.returncode,code);self.assertEqual(completed.stderr,b"")
            result=json.loads(completed.stdout);self.assertEqual(result["eligibility"],"HOLD")
            self.assertIs(result["publication_authorized"],False);self.assertNotIn(str(self.root),completed.stdout.decode())

    def binding(self):
        return json.loads((self.intake / "evidence-bindings.json").read_bytes())

    def legacy(self):
        # Invent a v1-shaped packet; never open or upgrade a historical record.
        (self.intake / "evidence-bindings.json").unlink()
        marker = json.loads((self.intake / "INTAKE-COMPLETE.json").read_bytes())
        marker["format"] = "outlands-source-export-intake-complete-v1"
        del marker["files"]["evidence-bindings.json"]
        write(self.intake / "INTAKE-COMPLETE.json", encoded(marker))

    def test_v2_strict_matches_exact_persisted_bindings(self):
        result = self.call(reads=2, require_bindings=True)
        self.assertEqual(result["bindings_status"], "MATCHED")
        self.assertEqual(result["packet_format"], "outlands-source-export-intake-complete-v2")
        self.assertEqual(result["limitations"], ["UNSIGNED_OWNER_STORAGE"])
        binding = self.binding()
        self.assertEqual(binding["selection_sha256"], hashlib.sha256(self.selection.read_bytes()).hexdigest())
        self.assertEqual(binding["policy"], {"gate_sha256": hashlib.sha256(Path(v.gate.__file__).read_bytes()).hexdigest(),
            "intake_sha256": hashlib.sha256(Path(v.builder.__file__).read_bytes()).hexdigest()})
        raw = (self.intake / "evidence-bindings.json").read_bytes()
        for payload in FILES.values(): self.assertNotIn(payload.strip(), raw)
        self.assertNotIn(str(self.root), raw.decode())

    def test_saved_policy_mismatch_each_hash_before_candidate_open(self):
        original = self.binding()
        for key in ("gate_sha256", "intake_sha256"):
            with self.subTest(key=key):
                value = json.loads(json.dumps(original)); value["policy"][key] = "0" * 64
                self.rebind("evidence-bindings.json", value)
                result = self.call("STALE", 0, no_candidate_open=True)
                self.assertEqual(result["reason_codes"], ["POLICY_CHANGED"])

    def test_current_policy_snapshot_mismatch_before_candidate_open(self):
        original = v.builder._policy_snapshot
        def drift(*args, **kwargs):
            values = original(*args, **kwargs)
            pin, _ = values["gate"]; values["gate"] = (pin, "0" * 64)
            return values
        with patch.object(v.builder, "_policy_snapshot", side_effect=drift):
            result = self.call("STALE", 0, no_candidate_open=True)
        self.assertEqual(result["reason_codes"], ["POLICY_CHANGED"])

    def test_binding_schema_resealed_invalid_fields_refuse_before_controls(self):
        original = self.binding()
        changes = [("format", "unknown"), ("selection_sha256", "X" * 64),
                   ("selection_sha256", True), ("selection_sha256", None),
                   ("proposal_sha256", "0" * 64), ("review_draft_sha256", "0" * 64),
                   ("policy", {"gate_sha256": "0" * 64}), ("policy", []),
                   ("files", []), ("files", None)]
        for key, replacement in changes:
            with self.subTest(key=key, replacement=replacement):
                value = json.loads(json.dumps(original)); value[key] = replacement
                self.rebind("evidence-bindings.json", value)
                with patch.object(v.gate, "_read_control", side_effect=AssertionError("opened control")) as control:
                    self.call("DAMAGED", 0, no_candidate_open=True)
                control.assert_not_called()

    def test_binding_missing_and_extra_fields_refuse(self):
        original = self.binding()
        for key in (*original, "extra"):
            with self.subTest(key=key):
                value = json.loads(json.dumps(original))
                if key == "extra": value[key] = "invented"
                else: del value[key]
                self.rebind("evidence-bindings.json", value)
                self.call("DAMAGED", 0, no_candidate_open=True)

    def test_malformed_resealed_binding_refuses_before_controls(self):
        for raw in (b"{", b'{"format":1,"format":2}', b'{"x":NaN}', b"[]", b"\xff", b" " * 262145):
            with self.subTest(size=len(raw)):
                write(self.intake / "evidence-bindings.json", raw)
                marker = json.loads((self.intake / "INTAKE-COMPLETE.json").read_bytes())
                marker["files"]["evidence-bindings.json"] = hashlib.sha256(raw).hexdigest()
                write(self.intake / "INTAKE-COMPLETE.json", encoded(marker))
                with patch.object(v.gate, "_read_control", side_effect=AssertionError("opened control")) as control:
                    self.call("DAMAGED", 0, no_candidate_open=True)
                control.assert_not_called()

    def test_binding_policy_extra_key_bad_hash_and_nonstring_refuse(self):
        for policy in ({"gate_sha256": "0"*64, "intake_sha256": "0"*64, "extra": "0"*64},
                       {"gate_sha256": "G"*64, "intake_sha256": "0"*64},
                       {"gate_sha256": 1, "intake_sha256": "0"*64}):
            with self.subTest(policy=policy):
                value = self.binding(); value["policy"] = policy
                self.rebind("evidence-bindings.json", value)
                self.call("DAMAGED", 0, no_candidate_open=True)

    def test_binding_file_declarations_must_match_including_numeric_types(self):
        original = self.binding()
        for key, replacement in (("path", "different.py"), ("artifact_kind", "documentation"),
                                 ("sha256", "0"*64), ("bytes", float(original["files"][0]["bytes"]))):
            with self.subTest(key=key):
                value = json.loads(json.dumps(original)); value["files"][0][key] = replacement
                self.rebind("evidence-bindings.json", value)
                self.call("DAMAGED", 0, no_candidate_open=True)

    def test_reformatted_selection_same_semantics_is_stale(self):
        original = self.selection.read_bytes()
        for raw in (json.dumps(self.doc, indent=4).encode(), original + b"\n\t"):
            with self.subTest(raw=raw):
                write(self.selection, raw)
                result = self.call("STALE", 0, no_candidate_open=True)
                self.assertEqual(result["reason_codes"], ["SELECTION_BYTES_CHANGED"])

    def test_unknown_packet_version_never_falls_back_to_legacy(self):
        marker = json.loads((self.intake / "INTAKE-COMPLETE.json").read_bytes())
        for version in ("outlands-source-export-intake-complete-v3", None, []):
            with self.subTest(version=version):
                marker["format"] = version; write(self.intake / "INTAKE-COMPLETE.json", encoded(marker))
                self.call("DAMAGED", 0, no_candidate_open=True)

    def test_v2_missing_binding_even_with_resealed_marker_is_damaged(self):
        self.legacy()
        marker = json.loads((self.intake / "INTAKE-COMPLETE.json").read_bytes())
        marker["format"] = "outlands-source-export-intake-complete-v2"
        write(self.intake / "INTAKE-COMPLETE.json", encoded(marker))
        self.call("DAMAGED", 0, no_candidate_open=True)

    def test_v1_with_binding_member_is_damaged(self):
        marker = json.loads((self.intake / "INTAKE-COMPLETE.json").read_bytes())
        marker["format"] = "outlands-source-export-intake-complete-v1"
        write(self.intake / "INTAKE-COMPLETE.json", encoded(marker))
        self.call("DAMAGED", 0, no_candidate_open=True)

    def test_legacy_consistent_has_explicit_unbound_limits(self):
        self.legacy()
        result = self.call(reads=2)
        self.assertEqual(result["bindings_status"], "LEGACY_UNBOUND")
        self.assertEqual(result["packet_format"], "outlands-source-export-intake-complete-v1")
        self.assertEqual(result["limitations"], ["UNSIGNED_OWNER_STORAGE", "EXACT_SELECTION_UNBOUND", "HISTORICAL_POLICY_UNBOUND"])

    def test_legacy_whitespace_selection_retains_semantic_only_checks(self):
        self.legacy(); write(self.selection, self.selection.read_bytes() + b" \n")
        self.assertEqual(self.call(reads=2)["bindings_status"], "LEGACY_UNBOUND")

    def test_strict_legacy_refusal_before_selection_or_candidate_access(self):
        self.legacy()
        with patch.object(v.gate, "_read_control", side_effect=AssertionError("opened control")) as control:
            result = self.call("DAMAGED", 0, require_bindings=True, no_candidate_open=True)
        control.assert_not_called()
        self.assertEqual(result["reason_codes"], ["BINDINGS_REQUIRED"])

    def test_coherent_downgrade_is_only_legacy_and_strict_mode_refuses(self):
        self.legacy()
        self.assertEqual(self.call(reads=2)["bindings_status"], "LEGACY_UNBOUND")
        self.call("DAMAGED", 0, require_bindings=True, no_candidate_open=True)

    def test_binding_link_and_hardlink_refuse_before_candidate(self):
        p = self.intake / "evidence-bindings.json"; raw = p.read_bytes(); p.unlink()
        p.symlink_to(self.selection); self.call("DAMAGED", 0, no_candidate_open=True)
        p.unlink(); write(p, raw)
        os.link(p, self.root / "binding-alias")
        self.call("DAMAGED", 0, no_candidate_open=True)

    def test_policy_drift_during_verification_stays_stale_and_held(self):
        original = v.builder._policy_snapshot; calls = []
        def drift(*args, **kwargs):
            value = original(*args, **kwargs); calls.append(True)
            if len(calls) == 2:
                pin, _ = value["intake"]; value["intake"] = (pin, "0"*64)
            return value
        with patch.object(v.builder, "_policy_snapshot", side_effect=drift):
            self.call("STALE", 2)

    def test_binding_tamper_after_content_reads_is_damaged(self):
        original = v.gate._read_member
        before = snapshot(self.candidate)
        def change(*args, **kwargs):
            raw = original(*args, **kwargs)
            write(self.intake / "evidence-bindings.json", b"{}")
            return raw
        with patch.object(v.gate, "_read_member", side_effect=change):
            result = v.verify_intake(self.candidate, self.selection, self.intake)
        self.assertEqual((result["status"], result["content_reads"], result["eligibility"]), ("DAMAGED", 2, "HOLD"))
        self.assertIs(result["publication_authorized"], False)
        self.assertEqual(snapshot(self.candidate), before)
        self.assertEqual((self.intake / "evidence-bindings.json").read_bytes(), b"{}")

    def test_nonboolean_strict_argument_is_refused(self):
        for value in (1, "yes", None):
            with self.subTest(value=value):
                self.call("DAMAGED", 0, require_bindings=value, no_candidate_open=True)

    def test_cli_strict_v2_and_legacy_refusal(self):
        for legacy, expected in ((False, "CONSISTENT"), (True, "DAMAGED")):
            if legacy: self.legacy()
            result = subprocess.run([sys.executable, "-I", "-B", str(Path(v.__file__)),
                "--candidate", str(self.candidate), "--selection", str(self.selection),
                "--intake", str(self.intake), "--require-bindings"], capture_output=True,
                timeout=20, check=False, cwd=self.root,
                env={"PATH":"/usr/bin:/bin", "LANG":"C.UTF-8", "PYTHONNOUSERSITE":"1"})
            self.assertEqual(result.returncode, 2 if legacy else 1)
            self.assertEqual(result.stderr, b"")
            value = json.loads(result.stdout)
            self.assertEqual(value["status"], expected)
            self.assertEqual(value["content_reads"], 0 if legacy else 2)
            self.assertIs(value["publication_authorized"], False)
            self.assertEqual(value["eligibility"], "HOLD")
            self.assertNotIn(str(self.root), result.stdout.decode())

if __name__=="__main__":unittest.main()
