"""Fundless Git fixtures prove source admission and binary compatibility guards."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


source = load("source", TOOLS / "check-build-source.py")
stage = load("stage", TOOLS / "stage-backend-candidate.py")


class Admission(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="smirk-git-admission-")
        self.previous = Path.cwd()
        os.chdir(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Fundless fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        Path("source.txt").write_text("baseline\n")
        self.git("add", ".")
        self.git("commit", "-qm", "baseline")
        self.base = self.git("rev-parse", "HEAD")
        Path("source.txt").write_text("candidate\n")
        self.git("commit", "-qam", "candidate")
        self.candidate = self.git("rev-parse", "HEAD")

    def tearDown(self):
        os.chdir(self.previous)
        self.temp.cleanup()

    def git(self, *args, input=None):
        return subprocess.check_output(["git", *args], input=input, text=True,
                                       stderr=subprocess.PIPE).strip()

    def wrapper(self, second=None, tree=None):
        tree = tree or self.git("rev-parse", self.candidate + "^{tree}")
        value = self.git("commit-tree", tree, "-p", self.base, "-p", second or self.candidate,
                         input="wrapper\n")
        self.git("reset", "--hard", value)
        return value

    def test_canonical_and_tree_identical_wrapper_admitted(self):
        self.assertEqual(source.admit(self.candidate)["build_commit"], self.candidate)
        wrapper = self.wrapper()
        admitted = source.admit(self.candidate, wrapper)
        self.assertEqual(admitted["source_commit"], self.candidate)
        self.assertEqual(admitted["source_tree"], self.git("rev-parse", "HEAD^{tree}"))

    def test_release_requires_wrapper_and_derives_its_source(self):
        with self.assertRaises(source.Refusal):
            source.source_for_checkout(True)
        with self.assertRaises(source.Refusal):
            source.admit(self.candidate, self.candidate, require_wrapper=True)
        wrapper = self.wrapper()
        self.assertEqual(source.source_for_checkout(True), self.candidate)
        self.assertEqual(source.admit(self.candidate, wrapper, require_wrapper=True)["build_commit"], wrapper)

    def test_moving_dispatch_head_refused(self):
        with self.assertRaises(source.Refusal):
            source.admit(self.candidate, self.base)

    def test_tree_change_refused(self):
        self.wrapper(tree=self.git("rev-parse", self.base + "^{tree}"))
        with self.assertRaises(source.Refusal):
            source.admit(self.candidate)

    def test_tree_identity_without_source_parent_refused(self):
        tree = self.git("rev-parse", self.candidate + "^{tree}")
        unrelated = self.git("commit-tree", tree, "-p", self.base, input="unrelated\n")
        self.wrapper(second=unrelated)
        with self.assertRaises(source.Refusal):
            source.admit(self.candidate)

    def test_dirty_surface_and_missing_pin_refused(self):
        Path("unknown.txt").write_text("unreviewed\n")
        with self.assertRaises(source.Refusal):
            source.admit(self.candidate)
        with self.assertRaises(source.Refusal):
            source.admit("")

    def test_dispatch_missing_head_or_wrong_repository_refused(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "Builds/smirk-backend-core",
                                    "GITHUB_EVENT_NAME": "workflow_dispatch"}, clear=True):
            with self.assertRaises(source.Refusal):
                source.main()
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "unreviewed/repository"}, clear=True):
            with self.assertRaises(source.Refusal):
                source.main()


class EventBoundary(unittest.TestCase):
    def setUp(self):
        self.head = "a" * 40
        self.environment = {"GITHUB_REPOSITORY": "Builds/smirk-backend-core",
                            "BUILD_LANE": "candidate", "GITHUB_EVENT_NAME": "workflow_dispatch",
                            "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": self.head,
                            "EXPECTED_BUILD_SHA": self.head}

    def test_exact_dispatch_event_admitted(self):
        self.assertEqual(source.build_context(self.environment), (self.head, True))

    def test_bad_ref_event_sha_or_malformed_input_refused(self):
        for key, value in (("GITHUB_REF", "refs/heads/topic"), ("GITHUB_EVENT_NAME", "push"),
                           ("GITHUB_SHA", "b" * 40), ("EXPECTED_BUILD_SHA", "main"),
                           ("EXPECTED_BUILD_SHA", "a" * 39), ("BUILD_LANE", "unknown")):
            with self.subTest(key=key, value=value), self.assertRaises(source.Refusal):
                source.build_context({**self.environment, key: value})

    def test_push_requires_main_and_exact_event_sha(self):
        env = {**self.environment, "BUILD_LANE": "ci", "GITHUB_EVENT_NAME": "push"}
        self.assertEqual(source.build_context(env), (self.head, True))
        with self.assertRaises(source.Refusal):
            source.build_context({**env, "GITHUB_REF": "refs/heads/topic"})

    def test_pr_binds_actual_event_head_and_target(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            event.write_text(json.dumps({"pull_request": {"head": {"sha": self.head}, "base": {"ref": "main"}}}))
            env = {**self.environment, "BUILD_LANE": "ci", "GITHUB_EVENT_NAME": "pull_request",
                   "GITHUB_EVENT_PATH": str(event)}
            self.assertEqual(source.build_context(env), (self.head, False))
            with self.assertRaises(source.Refusal):
                source.build_context({**env, "EXPECTED_BUILD_SHA": "b" * 40})
            event.write_text(json.dumps({"pull_request": {"head": {"sha": self.head}, "base": {"ref": "topic"}}}))
            with self.assertRaises(source.Refusal):
                source.build_context(env)

    def test_git_refusal_reports_bounded_underlying_cause(self):
        failure = subprocess.CalledProcessError(128, ["git"], stderr="fatal: object unavailable " + "x" * 2000)
        with patch.object(subprocess, "check_output", side_effect=failure):
            with self.assertRaises(source.Refusal) as caught:
                source.git("rev-parse", "HEAD")
        self.assertIn("object unavailable", str(caught.exception))
        self.assertLess(len(str(caught.exception)), 700)


class BinaryCompatibility(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="smirk-elf-fixture-")
        self.binary = Path(self.temp.name) / "binary"
        self.binary.write_bytes(b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00")

    def tearDown(self):
        self.temp.cleanup()

    def test_compatible_versions_recorded_in_numeric_order(self):
        with patch.object(subprocess, "check_output", return_value="GLIBC_2.3 GLIBC_2.36 GLIBC_2.9"):
            result = stage.elf_requirements(self.binary)
        self.assertEqual(result[-1], "2.36")
        self.assertIn("2.9", result)

    def test_incompatible_or_unknown_libc_refused(self):
        for output in ("GLIBC_2.38", "unreadable"):
            with self.subTest(output=output), patch.object(subprocess, "check_output", return_value=output):
                with self.assertRaises(stage.source.Refusal):
                    stage.elf_requirements(self.binary)

    def test_wrong_binary_format_refused_before_tool_invocation(self):
        self.binary.write_bytes(b"not ELF")
        with patch.object(subprocess, "check_output") as probe:
            with self.assertRaises(stage.source.Refusal):
                stage.elf_requirements(self.binary)
            probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
