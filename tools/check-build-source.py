#!/usr/bin/env python3
"""Admit one reviewed canonical source or its exact Builds merge wrapper."""
import os
import re
import subprocess
import sys


class Refusal(ValueError):
    pass


def git(*args):
    return subprocess.check_output(["git", *args], text=True, stderr=subprocess.PIPE).strip()


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


def main():
    if os.environ.get("GITHUB_REPOSITORY") != "Builds/smirk-backend-core":
        raise Refusal("this workflow is admitted only on Builds/smirk-backend-core")
    event = os.environ.get("GITHUB_EVENT_NAME")
    expected = os.environ.get("EXPECTED_BUILD_SHA")
    if not expected:
        raise Refusal("this build requires the exact reviewed event or dispatch head")
    if event not in {"push", "pull_request", "workflow_dispatch"}:
        raise Refusal("this build event is not admitted")
    wrapper = event != "pull_request"
    canonical = source_for_checkout(wrapper)
    result = admit(canonical, expected, require_wrapper=wrapper)
    print(f"Admitted canonical source {result['source_commit']} at Builds {result['build_commit']}")


if __name__ == "__main__":
    try:
        main()
    except Refusal as error:
        sys.exit(f"Build source refused: {error}")
    except subprocess.CalledProcessError:
        sys.exit("Build source refused: Git could not resolve the reviewed source or checkout")
