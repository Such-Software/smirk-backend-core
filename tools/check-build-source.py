#!/usr/bin/env python3
"""Admit one reviewed canonical source or its exact Builds merge wrapper."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys


class Refusal(ValueError):
    pass


def git(*args):
    try:
        return subprocess.check_output(["git", *args], text=True, stderr=subprocess.PIPE).strip()
    except subprocess.CalledProcessError as error:
        cause = " ".join((error.stderr or "Git returned no diagnostic").split())[:600]
        raise Refusal(f"Git evidence failed (exit {error.returncode}): {cause}") from None


def commit(value, label):
    if not re.fullmatch(r"[0-9a-f]{40}", value or ""):
        raise Refusal(f"{label} must be a reviewed full lowercase commit SHA")
    return value


def source_for_checkout(require_wrapper):
    if not require_wrapper:
        return git("rev-parse", "HEAD")
    parents = git("show", "-s", "--format=%P", "HEAD").split()
    if len(parents) != 2:
        raise Refusal("release or main CI requires a two-parent Builds wrapper")
    return commit(parents[1], "canonical source parent")


def admit(source, expected_head=None, require_wrapper=False):
    source = commit(source, "canonical source")
    head = git("rev-parse", "HEAD")
    if expected_head is not None and head != commit(expected_head, "expected_sha"):
        raise Refusal("checkout HEAD differs from the reviewed dispatch head")
    if git("rev-parse", f"{source}^{{commit}}") != source:
        raise Refusal("reviewed canonical source is not a commit")
    tree = git("rev-parse", f"{source}^{{tree}}")
    if git("rev-parse", "HEAD^{tree}") != tree:
        raise Refusal("Builds checkout tree differs from reviewed canonical source")
    if head != source or require_wrapper:
        parents = git("show", "-s", "--format=%P", "HEAD").split()
        if len(parents) != 2 or parents[1] != source:
            raise Refusal("Builds HEAD is neither canonical source nor its two-parent wrapper")
    if git("status", "--porcelain", "--untracked-files=all"):
        raise Refusal("Builds checkout contains local changes or untracked files")
    return {"source_commit": source, "build_commit": head, "source_tree": tree}


def build_context(environment):
    if environment.get("GITHUB_REPOSITORY") != "Builds/smirk-backend-core":
        raise Refusal("this workflow is admitted only on Builds/smirk-backend-core")
    event = environment.get("GITHUB_EVENT_NAME")
    lane = environment.get("BUILD_LANE")
    expected = commit(environment.get("EXPECTED_BUILD_SHA"), "expected event or dispatch SHA")
    if lane == "candidate":
        if event != "workflow_dispatch":
            raise Refusal("candidate builds require workflow_dispatch")
    elif lane == "ci":
        if event not in {"push", "pull_request"}:
            raise Refusal("fundless CI requires push or pull_request")
    else:
        raise Refusal("build lane is not admitted")
    if event == "pull_request":
        try:
            payload = json.loads(Path(environment.get("GITHUB_EVENT_PATH", "")).read_text())
            head = payload["pull_request"]["head"]["sha"]
            base = payload["pull_request"]["base"]["ref"]
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise Refusal(f"pull-request event evidence is unavailable: {type(error).__name__}") from None
        if head != expected or base != "main":
            raise Refusal("CI checkout does not match the exact main-targeted pull-request event head")
    elif environment.get("GITHUB_REF") != "refs/heads/main" or environment.get("GITHUB_SHA") != expected:
        raise Refusal("main event head must equal the reviewed full expected_sha")
    return expected, event != "pull_request"


def main():
    expected, wrapper = build_context(os.environ)
    canonical = source_for_checkout(wrapper)
    result = admit(canonical, expected, require_wrapper=wrapper)
    print(f"Admitted canonical source {result['source_commit']} at Builds {result['build_commit']}")


if __name__ == "__main__":
    try:
        main()
    except Refusal as error:
        sys.exit(f"Build source refused: {error}")
