#!/usr/bin/env python3
"""Build the library, then compile/run the warmed single-thread allocator probe.

Example: python3 bench/results/v6/allocation_probe.py --label before \
  --binary /tmp/secret-scan-v6-allocation-before \
  --output bench/results/v6/allocation-before.json
Select current rlibs from Cargo's JSON artifacts (including cached builds).
Frozen executables can be rerun with --run-only, without Cargo or dependency
discovery. Existing outputs/executables are never overwritten. Counters add
overhead: this is NOT a timing test.
"""
import argparse
import hashlib
import json
import platform
import subprocess
from pathlib import Path


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def current_rlibs(cargo_stdout):
    wanted = {"keyspoor", "serde_json", "blake3"}
    artifacts = {name: set() for name in wanted}
    for line in cargo_stdout.splitlines():
        event = json.loads(line)
        if event.get("reason") != "compiler-artifact":
            continue
        name = event["target"]["name"]
        if name in wanted:
            artifacts[name].update(
                Path(filename)
                for filename in event["filenames"]
                if filename.endswith(".rlib")
            )
    for name, paths in artifacts.items():
        if len(paths) != 1:
            raise RuntimeError(f"expected one current {name} rlib, found {len(paths)}")
    return {name: next(iter(paths)) for name, paths in artifacts.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, default=Path("target"))
    parser.add_argument("--run-only", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"refusing to overwrite output: {args.output}")
    root = Path(__file__).resolve().parents[3]
    source = Path(__file__).with_suffix(".rs")
    target_dir = (root / args.target_dir).resolve()
    release = target_dir / "release"
    binary = args.binary.resolve()
    provenance = binary.with_suffix(binary.suffix + ".provenance.json")
    if not args.run_only:
        if binary.exists() or provenance.exists():
            parser.error(f"refusing to overwrite executable or provenance: {binary}")
        cargo_command = ["cargo", "build", "--release", "--lib", "--locked", "--message-format=json", "--target-dir", str(target_dir)]
        cargo = subprocess.run(cargo_command, cwd=root, check=True, stdout=subprocess.PIPE, text=True)
        rlibs = current_rlibs(cargo.stdout)
        library = rlibs["keyspoor"]
        command = ["rustc", "--edition=2024", "-C", "opt-level=3", "-C", "lto=thin", "-C", "codegen-units=1", str(source), "-L", f"dependency={release / 'deps'}", "-o", str(binary)]
        for dependency in ("keyspoor", "serde_json", "blake3"):
            command.extend(["--extern", f"{dependency}={rlibs[dependency]}"])
        subprocess.run(command, cwd=root, check=True)
        build = {
            "source_sha256": sha256(source),
            "library_sha256": sha256(library),
            "git_head_at_build": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
            "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
            "cargo_build_command": cargo_command,
            "build_command": command,
            "dependency_rlibs": {name: {"path": str(rlibs[name]), "sha256": sha256(rlibs[name])} for name in ("serde_json", "blake3")},
            "binary_sha256": sha256(binary),
        }
        with provenance.open("x") as handle:
            handle.write(json.dumps(build, indent=2) + "\n")
    else:
        build = json.loads(provenance.read_text())
        if build["binary_sha256"] != sha256(binary):
            raise RuntimeError("frozen executable hash differs from build provenance")
    rows = []
    for count, encoding in ((1, "utf8"), (10000, "utf8"), (100000, "utf8"), (10000, "utf16le")):
        result = subprocess.run([str(binary), str(count), encoding], check=True, text=True, capture_output=True)
        rows.append(json.loads(result.stdout))
    payload = {
        "schema_version": 1,
        "label": args.label,
        "platform": platform.platform(),
        "build": build,
        "method": {
            "single_thread": True,
            "warmup_scans_per_case": 1,
            "engine_and_input_construction_excluded": True,
            "serialization_and_validation_excluded": True,
            "units": "requested allocator layout bytes; not RSS, usable size or copied bytes",
            "realloc": "successful new-size requests reported separately; live bytes change only by new size minus old size",
            "peak": "net live requested bytes above pre-scan baseline; transient System realloc internals are unobservable",
            "caveat": "process-global atomics; valid for this single-threaded probe, not concurrent unrelated allocations; counters perturb timing",
        },
        "cases": rows,
    }
    with args.output.open("x") as handle:
        handle.write(json.dumps(payload, indent=2) + "\n")
    print(f"{args.label}: {len(rows)} cases saved to {args.output}")


if __name__ == "__main__":
    main()
