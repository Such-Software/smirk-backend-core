#!/usr/bin/env python3
"""Stage a private Linux candidate with exact source and artifact provenance."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("build_source", ROOT / "tools/check-build-source.py")
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def elf_requirements(path):
    header = Path(path).read_bytes()[:20]
    if len(header) != 20 or header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\x3e\x00":
        raise source.Refusal("candidate must be a 64-bit little-endian x86_64 ELF binary")
    versions = subprocess.check_output(["readelf", "--version-info", str(path)], text=True)
    required = sorted(set(re.findall(r"\bGLIBC_([0-9]+(?:\.[0-9]+)+)\b", versions)),
                      key=lambda value: tuple(map(int, value.split("."))))
    if not required:
        raise source.Refusal("candidate has no readable GNU libc compatibility evidence")
    if tuple(map(int, required[-1].split("."))) > (2, 36):
        raise source.Refusal("candidate requires newer GNU libc than the admitted Debian 12 baseline")
    return required


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.chdir(ROOT)
    expected, wrapper = source.build_context(os.environ)
    if not wrapper or os.environ.get("BUILD_LANE") != "candidate":
        raise source.Refusal("artifact staging requires the admitted candidate dispatch lane")
    admitted = source.admit(source.source_for_checkout(True), expected, require_wrapper=True)
    binary = ROOT / "target/x86_64-unknown-linux-gnu/release/smirk-backend-core"
    required = elf_requirements(binary)
    rustc = subprocess.check_output(["rustc", "--version"], text=True).strip()
    if not rustc.startswith("rustc 1.98.0 "):
        raise source.Refusal("candidate compiler differs from the reviewed Rust 1.98.0 pin")
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    staged = args.output / "smirk-backend-core"
    shutil.copyfile(binary, staged)
    staged.chmod(0o755)
    manifest = {
        "schema_version": 1,
        "product": "smirk-backend-core",
        "publication": "private_candidate_only",
        **admitted,
        "canonical_repository": "https://github.com/Such-Software/smirk-backend-core",
        "build_repository": "Builds/smirk-backend-core",
        "workflow_path": ".gitea/workflows/backend-build.yml",
        "workflow_sha256": sha256(ROOT / ".gitea/workflows/backend-build.yml"),
        "cargo_lock_sha256": sha256(ROOT / "Cargo.lock"),
        "rust_toolchain_sha256": sha256(ROOT / "rust-toolchain.toml"),
        "rustc": rustc,
        "target": "x86_64-unknown-linux-gnu",
        "glibc_versions": required,
        "artifact": {"name": staged.name, "sha256": sha256(staged), "size": staged.stat().st_size},
    }
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"Staged private candidate for {admitted['source_commit']}; publication requires separate admission.")


if __name__ == "__main__":
    try:
        main()
    except source.Refusal as error:
        sys.exit(f"Candidate refused: {error}")
    except (OSError, subprocess.CalledProcessError):
        sys.exit("Candidate refused: required build output, compiler, or ELF evidence is unavailable")
