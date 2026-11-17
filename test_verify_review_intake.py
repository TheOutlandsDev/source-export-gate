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

    def call(self, status="CONSISTENT", reads=None):
        before = snapshot(self.root)
        original_open = os.open
        def readonly(path, flags, *a, **kw):
            if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                raise AssertionError("verifier attempted write")
            return original_open(path, flags, *a, **kw)
        with ExitStack() as stack:
            traps = [stack.enter_context(patch(target, side_effect=AssertionError("forbidden operation"))) for target in
                ("socket.socket", "socket.create_connection", "subprocess.Popen", "subprocess.run", "os.system", "os.fork", "os.kill", "os.killpg")]
            for name in ("assess", "_inventory", "_screen_snapshot"):
                traps.append(stack.enter_context(patch.object(v.gate, name, side_effect=AssertionError("forbidden assessment"))))
            stack.enter_context(patch("os.open", side_effect=readonly))
            member = stack.enter_context(patch.object(v.gate, "_read_member", wraps=v.gate._read_member))
            result = v.verify_intake(self.candidate, self.selection, self.intake)
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
        write(self.selection,self.selection.read_bytes()+b" ");self.call(reads=2)
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

if __name__=="__main__":unittest.main()
