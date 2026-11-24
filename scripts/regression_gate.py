#!/usr/bin/env python3
"""Corpus gates for deterministic output and managed-reference agreement.

Exit 0: completed and met configured thresholds. Exit 1: a gate failed.
Exit 2: missing input/tool or an invalid invocation. No corpus is bundled.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


class SetupError(Exception):
    pass


def require_file(path: Path, label: str) -> Path:
    if not path.is_file():
        raise SetupError(f"{label} does not exist: {path}")
    return path.resolve()


def invoke(argv: list[str], label: str, timeout: int = 1800) -> None:
    try:
        result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SetupError(f"{label} could not run: {error}") from error
    if result.returncode != 0:
        details = (result.stderr or result.stdout).strip()[-3500:]
        raise RuntimeError(f"{label} exited {result.returncode}: {details}")


def dump(cli: Path, binary: Path, metadata: Path, directory: Path, *, emit: bool) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    report = directory / "report.json"
    command = [str(cli), "--binary", str(binary), "--metadata", str(metadata),
               "--workers", "1", "--report", str(report)]
    if emit:
        command += ["--output-dir", str(directory / "project")]
    try:
        process = subprocess.run(command, text=True, capture_output=True, timeout=1800)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SetupError(f"il2cpprec CLI could not run: {error}") from error
    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"CLI did not produce a valid JSON report: {error}") from error
    methods = data.get("methods")
    if not isinstance(methods, list) or data.get("total") != len(methods):
        raise RuntimeError("CLI report has an invalid method list or total")
    expected_exit = 1 if data.get("errors", 0) else 0
    if process.returncode != expected_exit:
        details = (process.stderr or process.stdout).strip()[-3500:]
        raise RuntimeError(f"CLI exited {process.returncode}, expected {expected_exit}: {details}")
    return data


def method_manifest(report: dict[str, Any]) -> dict[str, str]:
    manifest: dict[str, str] = {}
    for method in report["methods"]:
        if not isinstance(method, dict):
            raise RuntimeError("CLI report contains a non-object method")
        identity = [method.get(k) for k in ("image", "index", "address", "name")]
        if identity[0] is None or identity[1] is None or identity[2] is None or identity[3] is None:
            raise RuntimeError("CLI report method has no stable identity")
        key = json.dumps(identity, ensure_ascii=False, separators=(",", ":"))
        if key in manifest:
            raise RuntimeError(f"duplicate method identity: {key}")
        payload = json.dumps(method, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        manifest[key] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return manifest


def file_manifest(directory: Path) -> dict[str, str]:
    return {
        str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.rglob("*")) if path.is_file()
    }


def run_determinism(args: argparse.Namespace, work: Path) -> dict[str, Any]:
    first = dump(args.cli, args.binary, args.metadata, work / "first", emit=True)
    second = dump(args.cli, args.binary, args.metadata, work / "second", emit=True)
    left, right = method_manifest(first), method_manifest(second)
    mismatches = [key for key in sorted(left.keys() | right.keys()) if left.get(key) != right.get(key)]
    project_left = file_manifest(work / "first" / "project")
    project_right = file_manifest(work / "second" / "project")
    changed_files = [key for key in sorted(project_left.keys() | project_right.keys())
                     if project_left.get(key) != project_right.get(key)]
    if not project_left or not project_right:
        raise RuntimeError("determinism runs produced no C# project files")
    return {
        "gate": "determinism", "methods": len(left),
        "mismatchedMethods": mismatches, "changedProjectFiles": changed_files,
        "status": "FAIL" if mismatches or changed_files else "PASS",
    }


def fingerprints(helper: Path, target: Path) -> dict[str, Any]:
    command = ["dotnet", "run", "--project", str(helper), "--", str(target)]
    try:
        result = subprocess.run(command, text=True, capture_output=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SetupError(f"managed fingerprint helper could not run: {error}") from error
    if result.returncode != 0:
        raise RuntimeError(f"managed fingerprint helper failed: {(result.stderr or result.stdout).strip()[-3500:]}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"managed fingerprint helper returned invalid JSON: {error}") from error
    if not isinstance(value, dict) or not isinstance(value.get("methods"), dict):
        raise RuntimeError("managed fingerprint helper returned no method map")
    return value


def run_differential(args: argparse.Namespace, work: Path) -> dict[str, Any]:
    if not args.managed or not args.managed.is_dir() or not list(args.managed.glob("*.dll")):
        raise SetupError("--managed must point to a directory containing original managed DLLs")
    if shutil.which("dotnet") is None:
        raise SetupError("dotnet SDK is required for the differential gate")
    report = dump(args.cli, args.binary, args.metadata, work / "recovery", emit=True)
    projects = list((work / "recovery" / "project").glob("*.csproj"))
    if len(projects) != 1:
        raise RuntimeError(f"expected one generated C# project, found {len(projects)}")
    output = work / "compiled"
    invoke(["dotnet", "build", str(projects[0]), "-o", str(output), "-nologo", "-v:q"],
           "generated C# project build")
    dll = output / (projects[0].stem + ".dll")
    require_file(dll, "recovered assembly")
    helper = ROOT / "scripts" / "ManagedFingerprint.csproj"
    original = fingerprints(helper, args.managed)
    recovered = fingerprints(helper, dll)
    a, b = original["methods"], recovered["methods"]
    targets = sorted({method["name"] for method in report["methods"]
                      if method.get("status") == "exact" and isinstance(method.get("name"), str)})
    target_prefixes = [name.rsplit("__", 1)[0] + "::" + name.rsplit("__", 1)[1] + "/"
                       for name in targets if "__" in name]
    matches: list[str] = []
    divergent: list[str] = []
    unmatched: list[str] = []
    for target in targets:
        if "__" not in target:
            unmatched.append(target)
            continue
        type_name, method_name = target.rsplit("__", 1)
        prefix = type_name + "::" + method_name + "/"
        originals = [key for key in a if key.startswith(prefix)]
        recovered_candidates = [key for key in b if key.startswith(prefix)]
        if len(originals) != 1 or len(recovered_candidates) != 1 or originals[0] != recovered_candidates[0]:
            unmatched.append(target)
            continue
        key = originals[0]
        matches.append(key)
        if a[key] != b[key]:
            divergent.append(key)
    if not matches:
        raise RuntimeError("no unambiguous recovered target methods matched the original managed DLLs")
    exact_count = len(matches) - len(divergent)
    agreement = exact_count / len(matches)
    floor = args.min_agreement
    return {
        "gate": "differential", "targetMethods": len(targets), "matched": len(matches),
        "exactNamedReferenceMatches": exact_count,
        "agreement": agreement, "minimumAgreement": floor,
        "unmatchedTargets": unmatched[:50], "divergentMethods": divergent[:50],
        "ambiguousOriginalMethods": [key for key in original.get("ambiguous", [])
                                     if any(key.startswith(prefix) for prefix in target_prefixes)],
        "ambiguousRecoveredMethods": [key for key in recovered.get("ambiguous", [])
                                      if any(key.startswith(prefix) for prefix in target_prefixes)],
        "status": ("OBSERVED" if floor is None else
                   "FAIL" if agreement < floor else "PASS"),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gate", choices=("determinism", "differential"))
    parser.add_argument("--cli", type=Path, default=ROOT / "build" / "il2cpprec_cli")
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--managed", type=Path, help="original managed DLL directory (differential only)")
    parser.add_argument("--min-agreement", type=float, help="fail if named-reference agreement is below this 0..1 fraction")
    parser.add_argument("--report", type=Path, help="write gate result as JSON")
    args = parser.parse_args()
    if args.min_agreement is not None and not 0 <= args.min_agreement <= 1:
        parser.error("--min-agreement must be between 0 and 1")
    if args.gate == "differential" and args.managed is None:
        parser.error("differential gate requires --managed")
    if args.gate == "determinism" and (args.managed or args.min_agreement is not None):
        parser.error("--managed and --min-agreement apply only to differential")
    return args


def main() -> int:
    args = parse_args()
    try:
        args.cli = require_file(args.cli, "CLI")
        args.binary = require_file(args.binary, "binary")
        args.metadata = require_file(args.metadata, "metadata")
        with tempfile.TemporaryDirectory(prefix="il2cpprec-gate-") as directory:
            result = (run_determinism(args, Path(directory)) if args.gate == "determinism"
                      else run_differential(args, Path(directory)))
    except SetupError as error:
        print(f"SETUP ERROR: {error}", file=sys.stderr)
        return 2
    except RuntimeError as error:
        print(f"GATE ERROR: {error}", file=sys.stderr)
        return 1
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in ("PASS", "OBSERVED") else 1


if __name__ == "__main__":
    raise SystemExit(main())
