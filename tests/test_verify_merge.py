"""Real local Git fixtures; these cases are not live GitHub acceptance."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).absolute().parent.parent
SOURCE_FILES = (
    ".gitignore", ".github/workflows/ci.yml", "README.md", "canary.txt",
    "canary_app.py", "tools/verify_merge.py", "tests/test_canary_app.py",
    "tests/test_verify_merge.py",
)


class LocalMerge:
    def __init__(self, directory):
        self.root = Path(directory)
        self.repository = self.root / "candidate"
        self.trusted = self.root / "trusted"
        self.repository.mkdir()
        self.trusted.mkdir()
        for name in SOURCE_FILES:
            for destination in (self.repository, self.trusted):
                (destination / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination / name)
        self.environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self.environment.update({
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "Canary fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Canary fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "GIT_AUTHOR_DATE": "2026-11-01T00:00:00Z", "GIT_COMMITTER_DATE": "2026-11-01T00:00:00Z",
        })
        self.git("init", "--initial-branch=main")
        self.git("config", "core.fileMode", "true")
        self.git("add", ".")
        self.git("commit", "--no-gpg-sign", "-m", "Reviewed fixture base")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.base_ref = "refs/heads/main"
        self.head_ref = "refs/heads/canary/positive"
        self.git("checkout", "-b", "canary/positive")
        (self.repository / "canary.txt").write_text("canary=positive-001\n")
        self.commit_head()
        self.manifest_path = self.root / "reviewed-base.json"
        self.manifest = {
            "kind": "exacly-canary-trusted-base", "schema_version": "1",
            "base_ref": self.base_ref, "base_revision": self.base, "files": self.inventory(self.base),
        }
        self.save_manifest()

    def git(self, *arguments, binary=False):
        result = subprocess.run(
            ["git", "-c", "core.hooksPath=" + os.devnull, "-C", str(self.repository), *arguments],
            env=self.environment, stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=True,
        )
        return result.stdout if binary else result.stdout.decode()

    def inventory(self, revision):
        result = {}
        for entry in self.git("ls-tree", "-r", "-z", revision, binary=True).split(b"\0"):
            if entry:
                meta, name = entry.split(b"\t", 1)
                mode, kind, oid = meta.decode().split()
                if kind != "blob":
                    raise AssertionError("fixture base has a non-blob file")
                data = self.git("cat-file", "blob", oid, binary=True)
                result[name.decode()] = {"mode": mode, "blob": oid, "sha256": "sha256:" + hashlib.sha256(data).hexdigest()}
        return dict(sorted(result.items()))

    def save_manifest(self):
        self.manifest_path.write_text(json.dumps(self.manifest, sort_keys=True, indent=2) + "\n")
        self.pin = "sha256:" + hashlib.sha256(self.manifest_path.read_bytes()).hexdigest()

    def commit_head(self):
        self.git("add", ".")
        self.git("commit", "--no-gpg-sign", "-m", "Fixture canary change")
        self.head = self.git("rev-parse", "HEAD").strip()
        self.tree = self.git("rev-parse", "HEAD^{tree}").strip()
        self.merge = self.git("commit-tree", self.tree, "-p", self.base, "-p", self.head, "-m", "Fixture merge").strip()

    def run(self, overrides=None):
        arguments = {
            "repository": str(self.repository), "manifest": str(self.manifest_path),
            "manifest-sha256": self.pin, "base-ref": self.base_ref,
            "head-ref": self.head_ref, "base": self.base, "head": self.head,
            "merge": self.merge, "tree": self.tree,
        }
        arguments.update(overrides or {})
        command = [sys.executable, "-I", "-B", str(self.trusted / "tools/verify_merge.py")]
        for key, value in arguments.items():
            command += ["--" + key, value]
        result = subprocess.run(command, capture_output=True, timeout=25, env=self.environment)
        if result.stderr:
            raise AssertionError(result.stderr.decode())
        return result.returncode, json.loads(result.stdout)


class MergeVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="canary-verifier-")
        self.addCleanup(self.temporary.cleanup)
        self.case = LocalMerge(self.temporary.name)

    def reject(self, overrides=None, reason=None):
        status, report = self.case.run(overrides)
        self.assertEqual(status, 1, report)
        self.assertEqual(report["status"], "rejected", report)
        if reason:
            self.assertIn(reason, report["reason"])
        return report

    def test_actual_merge_data_and_fixed_trusted_tests_are_verified(self):
        before = self.case.git("show-ref")
        status, report = self.case.run()
        self.assertEqual(status, 0, report)
        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["merge_revision"], self.case.merge)
        self.assertEqual(report["merge_tree"], self.case.tree)
        self.assertEqual(report["merge_parents"], [self.case.base, self.case.head])
        self.assertEqual(report["trusted_tests"]["cases"], 7)
        self.assertEqual(report["trusted_tests"]["result"], "passed")
        self.assertIn("Ran 7 tests", report["trusted_tests"]["output"])
        self.assertFalse(report["candidate_code_executed"])
        self.assertEqual(report["provider_writes"], 0)
        self.assertEqual(report["canary_delta"]["label"], "positive-001")
        self.assertEqual(report["manifest_sha256"], self.case.pin)
        self.assertEqual(before, self.case.git("show-ref"))

    def test_changed_base_pin_is_rejected(self):
        self.reject({"base": self.case.head}, "B/H/M must be distinct")

    def test_current_base_ref_change_is_rejected(self):
        self.case.git("update-ref", self.case.base_ref, self.case.head)
        self.reject(reason="current local base ref changed")

    def test_changed_head_pin_is_rejected(self):
        self.reject({"head": self.case.merge}, "B/H/M must be distinct")

    def test_current_head_ref_change_is_rejected(self):
        self.case.git("update-ref", self.case.head_ref, self.case.base)
        self.reject(reason="current local head ref changed")

    def test_reversed_merge_parents_are_rejected(self):
        wrong = self.case.git("commit-tree", self.case.tree, "-p", self.case.head, "-p", self.case.base, "-m", "Wrong parents").strip()
        self.reject({"merge": wrong}, "ordered B/H")

    def test_one_parent_merge_is_rejected(self):
        wrong = self.case.git("commit-tree", self.case.tree, "-p", self.case.base, "-m", "Missing head parent").strip()
        self.reject({"merge": wrong}, "ordered B/H")

    def test_wrong_selected_tree_is_rejected(self):
        wrong = self.case.git("rev-parse", self.case.base + "^{tree}").strip()
        self.reject({"tree": wrong}, "merge tree differs")

    def test_code_test_workflow_verifier_and_readme_changes_are_rejected(self):
        for name in ("canary_app.py", "tests/test_canary_app.py", ".github/workflows/ci.yml", "tools/verify_merge.py", "README.md"):
            with self.subTest(path=name), tempfile.TemporaryDirectory(prefix="canary-change-") as temporary:
                case = LocalMerge(temporary)
                with (case.repository / name).open("a") as file:
                    file.write("\n# Candidate modification\n")
                case.commit_head()
                status, report = case.run()
                self.assertEqual(status, 1, report)
                self.assertIn("changed protected source", report["reason"])

    def test_unexpected_file_is_rejected(self):
        (self.case.repository / "extra.py").write_text("raise RuntimeError('never execute candidate code')\n")
        self.case.commit_head()
        self.reject(reason="unexpected files")

    def test_missing_file_is_rejected(self):
        (self.case.repository / "README.md").unlink()
        self.case.commit_head()
        self.reject(reason="unexpected files")

    def test_symlink_is_rejected(self):
        (self.case.repository / "canary.txt").unlink()
        (self.case.repository / "canary.txt").symlink_to("README.md")
        self.case.commit_head()
        self.reject(reason="links, submodules and executable modes")

    def test_executable_mode_is_rejected(self):
        (self.case.repository / "canary_app.py").chmod(0o755)
        self.case.commit_head()
        self.reject(reason="links, submodules and executable modes")

    def test_submodule_mode_is_rejected(self):
        self.case.git("update-index", "--add", "--cacheinfo", "160000," + self.case.base + ",foreign-module")
        self.case.git("commit", "--no-gpg-sign", "-m", "Untrusted gitlink")
        self.case.head = self.case.git("rev-parse", "HEAD").strip()
        self.case.tree = self.case.git("rev-parse", "HEAD^{tree}").strip()
        self.case.merge = self.case.git("commit-tree", self.case.tree, "-p", self.case.base, "-p", self.case.head, "-m", "Gitlink merge").strip()
        self.reject(reason="links, submodules and executable modes")

    def test_multiple_lines_or_non_ascii_canary_are_rejected(self):
        for data in (b"canary=valid\nextra=value\n", "canary=\u00e9\n".encode(), b"canary=" + b"x" * 40 + b"\n", b"canary=UPPERCASE\n"):
            with self.subTest(data=data), tempfile.TemporaryDirectory(prefix="canary-label-") as temporary:
                case = LocalMerge(temporary)
                (case.repository / "canary.txt").write_bytes(data)
                case.commit_head()
                status, report = case.run()
                self.assertEqual(status, 1, report)
                self.assertIn("canary", report["reason"])

    def test_manifest_bytes_must_match_outside_pin(self):
        with self.case.manifest_path.open("a") as file:
            file.write(" ")
        self.reject(reason="manifest differs")

    def test_manifest_in_candidate_directory_is_rejected(self):
        path = self.case.repository / "candidate-selected-manifest.json"
        shutil.copyfile(self.case.manifest_path, path)
        self.reject({"manifest": str(path)}, "outside candidate repository")

    def test_manifest_claiming_wrong_blob_is_rejected(self):
        self.case.manifest["files"]["canary_app.py"]["blob"] = self.case.head
        self.case.save_manifest()
        self.reject(reason="base inventory differs")

    def test_duplicate_manifest_key_is_rejected(self):
        raw = self.case.manifest_path.read_text()
        self.case.manifest_path.write_text('{"kind":"other",' + raw.lstrip()[1:])
        pin = "sha256:" + hashlib.sha256(self.case.manifest_path.read_bytes()).hexdigest()
        self.reject({"manifest-sha256": pin}, "duplicate manifest key")

    def test_trusted_source_drift_is_rejected(self):
        with (self.case.trusted / "canary_app.py").open("a") as file:
            file.write("\n# Changed trusted installation\n")
        self.reject(reason="trusted source bytes differ")

    def test_trusted_source_symlink_is_rejected(self):
        source = self.case.trusted / "canary_app.py"
        source.unlink()
        source.symlink_to(self.case.repository / "canary_app.py")
        self.reject(reason="trusted source links")

    def test_unexpected_trusted_source_is_rejected(self):
        (self.case.trusted / "unknown.py").write_text("raise RuntimeError('not trusted')\n")
        self.reject(reason="trusted source has missing or unexpected files")

    def test_candidate_code_is_not_executed(self):
        marker = self.case.root / "candidate-executed"
        (self.case.repository / "canary_app.py").write_text("from pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\n")
        self.case.commit_head()
        self.reject(reason="changed protected source")
        self.assertFalse(marker.exists())

    def test_only_matching_head_and_merge_canary_delta_is_permitted(self):
        previous_tree = self.case.tree
        (self.case.repository / "canary.txt").write_text("canary=other-002\n")
        self.case.commit_head()
        self.case.tree = previous_tree
        self.case.merge = self.case.git("commit-tree", previous_tree, "-p", self.case.base, "-p", self.case.head, "-m", "Different canary").strip()
        self.reject(reason="matching head/merge canary delta")


if __name__ == "__main__":
    unittest.main()
