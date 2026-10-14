import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "cmake/WasmSourceStamp.cmake"
CMAKE = sys.argv.pop(1) if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "cmake"
GIT = shutil.which("git")


class WasmSourceStampTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="anyps5-wasm-stamp-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name) / "source with spaces"
        self.source = self.root / "core/relinker/example.cpp"
        self.source.parent.mkdir(parents=True)
        self.source.write_text("int example() { return 1; }\n", encoding="utf-8")
        self.stamp = Path(directory.name) / "stamp with spaces.hpp"
        self.environment = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0", GIT_CEILING_DIRECTORIES=str(self.root.parent))

    def git(self, *arguments):
        result = subprocess.run([GIT, "-C", str(self.root), *arguments], env=self.environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def initialize_git(self):
        if GIT is None:
            self.skipTest("Git is unavailable")
        self.git("init", "--quiet")
        self.git("config", "user.name", "AnyPS5 test")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("add", "core/relinker/example.cpp")
        self.git("commit", "--quiet", "-m", "initial fixture")
        return self.git("rev-parse", "HEAD")

    def update_stamp(self, git=None):
        result = subprocess.run([
            CMAKE, f"-DGIT_EXECUTABLE={git or GIT or 'git-unavailable'}", f"-DSOURCE_ROOT={self.root}",
            f"-DSTAMP_PATH={self.stamp}", "-P", str(SCRIPT),
        ], env=self.environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        content = self.stamp.read_text(encoding="utf-8")
        commit = re.search(r'^#define ANYPS5_WASM_SOURCE_COMMIT "([a-f0-9]*)"$', content, re.MULTILINE)
        dirty = re.search(r"^#define ANYPS5_WASM_SOURCE_DIRTY (-?\d+)$", content, re.MULTILINE)
        self.assertIsNotNone(commit, content)
        self.assertIsNotNone(dirty, content)
        return commit.group(1), int(dirty.group(1))

    def test_commit_and_dirty_state_follow_compiled_source_changes(self):
        first_commit = self.initialize_git()
        self.assertEqual(self.update_stamp(), (first_commit, 0))
        self.source.write_text("int example() { return 2; }\n", encoding="utf-8")
        self.assertEqual(self.update_stamp(), (first_commit, 1))
        self.git("add", "core/relinker/example.cpp")
        self.assertEqual(self.update_stamp(), (first_commit, 1))
        self.git("commit", "--quiet", "-m", "change fixture")
        second_commit = self.git("rev-parse", "HEAD")
        self.assertNotEqual(first_commit, second_commit)
        self.assertEqual(self.update_stamp(), (second_commit, 0))

    def test_untracked_relinker_sources_mark_the_build_dirty(self):
        commit = self.initialize_git()
        (self.source.parent / "new.cpp").write_text("int added() { return 3; }\n", encoding="utf-8")
        self.assertEqual(self.update_stamp(), (commit, 1))

    def test_unrelated_untracked_and_tracked_files_do_not_mark_source_dirty(self):
        commit = self.initialize_git()
        unrelated = self.root / "unrelated.txt"
        unrelated.write_text("untracked\n", encoding="utf-8")
        self.assertEqual(self.update_stamp(), (commit, 0))
        self.git("add", "unrelated.txt")
        self.git("commit", "--quiet", "-m", "unrelated fixture")
        commit = self.git("rev-parse", "HEAD")
        unrelated.write_text("modified\n", encoding="utf-8")
        self.assertEqual(self.update_stamp(), (commit, 0))

    def test_stamp_script_changes_mark_source_dirty(self):
        self.initialize_git()
        script = self.root / "cmake/WasmSourceStamp.cmake"
        script.parent.mkdir()
        script.write_text("set(example 1)\n", encoding="utf-8")
        self.git("add", "cmake/WasmSourceStamp.cmake")
        self.git("commit", "--quiet", "-m", "stamp fixture")
        commit = self.git("rev-parse", "HEAD")
        self.assertEqual(self.update_stamp(), (commit, 0))
        script.write_text("set(example 2)\n", encoding="utf-8")
        self.assertEqual(self.update_stamp(), (commit, 1))

    def test_non_git_checkout_has_unknown_commit_and_dirty_state(self):
        self.assertEqual(self.update_stamp(), ("", -1))

    def test_missing_git_has_unknown_commit_and_dirty_state(self):
        self.assertEqual(self.update_stamp(git=str(self.root / "missing git executable")), ("", -1))

    def test_unchanged_stamp_preserves_modification_time(self):
        commit = self.initialize_git()
        self.assertEqual(self.update_stamp(), (commit, 0))
        previous = self.stamp.read_bytes()
        old_time = 946684800000000000
        os.utime(self.stamp, ns=(old_time, old_time))
        timestamp = self.stamp.stat().st_mtime_ns
        self.assertEqual(self.update_stamp(), (commit, 0))
        self.assertEqual(self.stamp.read_bytes(), previous)
        self.assertEqual(self.stamp.stat().st_mtime_ns, timestamp)


if __name__ == "__main__":
    unittest.main()
