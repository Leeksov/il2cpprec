#!/usr/bin/env python3
"""Measure native recovery, emitted C#, and compilation on one caller-supplied corpus.

Exit 0 means the gate passed (or --observe completed); 1 means a measured
regression or compiler failure; 2 means required input/tooling was unavailable.
The program never bundles or copies the supplied binary into the repository.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STATUSES = ("exact", "partial", "error")
EMISSION_STATUSES = ("supported", "partial", "unsupported", "declaration-only", "omitted")
CS_ERROR = re.compile(r"^(.+?): error (CS\d+): (.*?)(?: \[[^\]]+\])?$", re.MULTILINE)
GATE_OWNED_FLAGS = frozenset({"--binary", "--metadata", "--include-images", "--output-dir", "--report", "--verify"})


class SetupError(RuntimeError):
    pass


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def required_file(value: Path | None, label: str) -> Path:
    if value is None or not value.is_file():
        raise SetupError(f"{label} must be an existing file: {value}")
    return value.resolve()


def nonnegative(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"invalid {label}: {value!r}")
    return value


def reason_group(reason: str) -> str:
    if reason.startswith("native register '") and reason.endswith("' has no managed ABI value"):
        return reason
    if reason.startswith("parameter '"):
        return "parameter ABI conversion or binding"
    if reason.startswith("Managed value '"):
        return "managed value ABI conversion"
    if reason.startswith("Return type '"):
        return "return type ABI conversion"
    return re.sub(r"0x[0-9A-Fa-f]+", "0xADDR", reason)


def counted_rows(counter: Counter[str], *, limit: int = 30) -> list[dict[str, Any]]:
    return [{"reason": name, "count": count}
            for name, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit]]


def summarize_cli(report: dict[str, Any], image: str) -> dict[str, Any]:
    methods = report.get("methods")
    if not isinstance(methods, list) or nonnegative(report.get("total"), "total") != len(methods):
        raise ValueError("CLI report has an invalid method list or total")
    for key in ("exact", "partial", "errors"):
        nonnegative(report.get(key), key)
    by_image: dict[str, Counter[str]] = defaultdict(Counter)
    native_reasons: Counter[str] = Counter()
    for method in methods:
        if not isinstance(method, dict) or method.get("status") not in STATUSES:
            raise ValueError("CLI report has an invalid method status")
        name = method.get("image") or "<unknown>"
        by_image[name][method["status"]] += 1
        if name == image:
            for reason in method.get("reasons", []):
                if isinstance(reason, str):
                    native_reasons[reason_group(reason)] += 1
    totals = Counter(method["status"] for method in methods)
    if (totals["exact"], totals["partial"], totals["error"]) != (
        report["exact"], report["partial"], report["errors"]
    ):
        raise ValueError("CLI report aggregate counts disagree with method statuses")
    target = by_image.get(image, Counter())
    if not target:
        raise ValueError(f"target image {image!r} has no resolved methods")
    emission = report.get("projectEmission")
    if not isinstance(emission, dict) or emission.get("scope") != "native-exact-inputs":
        raise ValueError("CLI report has no native-exact C# emission details")
    selected = report.get("options", {}).get("includedImages")
    if selected != [image]:
        raise ValueError(f"project emission cannot be attributed to {image!r}: includedImages={selected!r}")
    emitted = emission.get("methods")
    if not isinstance(emitted, list):
        raise ValueError("project emission has no method list")
    emission_counts: Counter[str] = Counter()
    emission_reasons: Counter[str] = Counter()
    image_counts: dict[str, Counter[str]] = defaultdict(Counter)
    image_reasons: dict[str, Counter[str]] = defaultdict(Counter)
    explicit_images = any(isinstance(method, dict) and "image" in method for method in emitted)
    for method in emitted:
        if not isinstance(method, dict) or method.get("status") not in EMISSION_STATUSES:
            raise ValueError("project emission contains an invalid method status")
        status = method["status"]
        emission_counts[status] += 1
        if explicit_images:
            emitted_image = method.get("image")
            if not isinstance(emitted_image, str) or not emitted_image.strip():
                raise ValueError("project emission requires a nonempty image for every method")
            image_counts[emitted_image][status] += 1
        reason = method.get("reason")
        if status != "supported" and isinstance(reason, str) and reason:
            grouped = f"{status}: {reason_group(reason)}"
            emission_reasons[grouped] += 1
            if explicit_images:
                image_reasons[emitted_image][grouped] += 1
    for status in EMISSION_STATUSES:
        field = "declarationOnly" if status == "declaration-only" else status
        if nonnegative(emission.get(field), f"projectEmission.{field}") != emission_counts[status]:
            raise ValueError(f"project emission {status} count disagrees with method list")
    if explicit_images:
        attribution = "explicit-image"
        target_emission = image_counts.get(image, Counter())
        target_reasons = image_reasons.get(image, Counter())
    else:
        # Older reports are attributable only when the writer emitted exactly
        # the native-exact methods in the sole requested image. Address reuse
        # across assemblies is never used as a substitute for image identity.
        if report.get("options", {}).get("fullDeclarations") or len(emitted) != target["exact"]:
            raise ValueError("project emission lacks per-method image identity for this scope")
        attribution = "legacy-filter"
        target_emission = emission_counts
        target_reasons = emission_reasons
        image_counts[image] = emission_counts
        image_reasons[image] = emission_reasons
    if sum(target_emission.values()) != target["exact"]:
        raise ValueError("target-image project emission does not cover each native-exact method")

    def emitted_summary(counts: Counter[str], reasons: Counter[str]) -> dict[str, Any]:
        return {"methods": sum(counts.values()), "supported": counts["supported"],
                "partial": counts["partial"], "unsupported": counts["unsupported"],
                "declarationOnly": counts["declaration-only"], "omitted": counts["omitted"],
                "reasons": counted_rows(reasons)}

    return {
        "allMethods": {"total": len(methods), "exact": totals["exact"],
                       "partial": totals["partial"], "errors": totals["error"]},
        "targetImage": {"name": image, "total": sum(target.values()),
                        "exact": target["exact"], "partial": target["partial"],
                        "errors": target["error"], "nativeReasons": counted_rows(native_reasons)},
        "images": [{"name": name, "total": sum(counts.values()),
                    "exact": counts["exact"], "partial": counts["partial"],
                    "errors": counts["error"]}
                   for name, counts in sorted(by_image.items())],
        "csharp": {"scope": "target-image", "attribution": attribution,
                   **emitted_summary(target_emission, target_reasons)},
        "csharpAllImages": {"scope": "native-exact-inputs", **emitted_summary(emission_counts, emission_reasons),
                             "images": [{"name": name, **emitted_summary(counts, image_reasons.get(name, Counter()))}
                                        for name, counts in sorted(image_counts.items())]},
        "profile": {key: report.get("sourceProfile", {}).get(key)
                    for key in ("id", "variant", "confidence", "selectionMode")},
    }


def project_digest(directory: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(p for p in directory.rglob("*") if p.is_file() and not {"obj", "bin"} & set(p.parts))
    for path in files:
        relative = path.relative_to(directory).as_posix().encode()
        digest.update(len(relative).to_bytes(4, "little"))
        digest.update(relative)
        digest.update(bytes.fromhex(file_hash(path)))
    return digest.hexdigest()


def parse_compiler_output(output: str, exit_code: int, project_dir: Path) -> dict[str, Any]:
    errors: set[tuple[str, str, str]] = set()
    for match in CS_ERROR.finditer(output):
        source = match.group(1).replace(str(project_dir), "<PROJECT>")
        errors.add((source, match.group(2), match.group(3).strip()))
    codes = Counter(code for _, code, _ in errors)
    summary = re.findall(r"(?m)^\s*(\d+) Error\(s\)\s*$", output)
    if exit_code != 0 and not errors and not summary:
        raise RuntimeError("dotnet build failed without parseable compiler errors: " + output[-1200:])
    return {
        "status": "PASS" if exit_code == 0 else "FAIL",
        "errors": len(errors) if errors else (int(summary[-1]) if summary else 0),
        "codes": [{"code": code, "count": count}
                  for code, count in sorted(codes.items(), key=lambda item: (-item[1], item[0]))],
        "sample": [{"source": source, "code": code, "message": message}
                   for source, code, message in sorted(errors)[:12]],
    }


def compiler_result(project_dir: Path) -> dict[str, Any]:
    if shutil.which("dotnet") is None:
        raise SetupError("dotnet SDK is required to check generated C#")
    projects = sorted(project_dir.glob("*.csproj"))
    if len(projects) != 1:
        raise SetupError(f"expected one C# project in {project_dir}, found {len(projects)}")
    try:
        result = subprocess.run(
            ["dotnet", "build", str(projects[0]), "-nologo", "-v:q"],
            text=True, capture_output=True, timeout=900,
            env={**os.environ, "DOTNET_CLI_TELEMETRY_OPTOUT": "1"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SetupError(f"dotnet build could not run: {error}") from error
    return parse_compiler_output(result.stdout + "\n" + result.stderr,
                                 result.returncode, project_dir)


def oracle_result(script: Path | None, cli: Path) -> dict[str, Any]:
    if script is None:
        return {"status": "SKIP", "passed": 0, "failed": 0, "skipped": 0}
    script = required_file(script, "oracle script")
    try:
        result = subprocess.run([sys.executable, str(script), "--cli", str(cli)],
                                text=True, capture_output=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SetupError(f"private oracle could not run: {error}") from error
    lines = result.stdout.splitlines() + result.stderr.splitlines()
    passed = sum(line.startswith("PASS exact ") for line in lines)
    failed = sum(line.startswith("FAIL ") for line in lines)
    skipped = sum(line.startswith("SKIP ") for line in lines)
    status = "PASS" if result.returncode == 0 and passed > 0 and failed == 0 else "FAIL"
    return {"status": status, "passed": passed, "failed": failed, "skipped": skipped}


def compare_baseline(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    if baseline.get("runner") != "il2cpprec-corpus-gate" or baseline.get("schemaVersion") != 1:
        raise SetupError("baseline is not an il2cpprec corpus gate report")
    if baseline.get("input") != current["input"] or baseline.get("targetImage", {}).get("name") != current["targetImage"]["name"]:
        raise SetupError("baseline input hashes or target image differ")
    if baseline.get("cliArguments", []) != current["cliArguments"] or baseline.get("cliOptions", {}) != current["cliOptions"]:
        raise SetupError("baseline CLI arguments or effective options differ")
    keys = ("supported", "partial", "unsupported", "omitted")
    csharp_delta = {key: current["csharp"][key] - baseline["csharp"][key] for key in keys}
    return {"csharpDelta": csharp_delta,
            "nativeExactDelta": current["targetImage"]["exact"] - baseline["targetImage"]["exact"],
            "compilerErrorDelta": current["compiler"]["errors"] - baseline["compiler"]["errors"],
            "projectChanged": current["projectSha256"] != baseline.get("projectSha256")}


def gate_status(failures: list[str], observe: bool) -> str:
    if not failures:
        return "PASS"
    if observe and failures == ["generated C# project does not compile"]:
        return "OBSERVED"
    return "FAIL"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--image", default="Assembly-CSharp.dll")
    parser.add_argument("--cli", type=Path, default=ROOT / "build" / "il2cpprec_cli")
    parser.add_argument("--cli-arg", action="append", default=[], metavar="ARG",
                        help="extra CLI argument; repeatable, e.g. --cli-arg=--full-metadata")
    parser.add_argument("--existing-report", type=Path,
                        help="summarize an existing CLI JSON report and generated project")
    parser.add_argument("--existing-project", type=Path)
    parser.add_argument("--oracle-script", type=Path,
                        help="optional private script; PASS exact/FAIL/SKIP output is counted")
    parser.add_argument("--baseline", type=Path, help="previous corpus gate JSON for regression comparison")
    parser.add_argument("--report", type=Path, help="write deterministic summary JSON")
    parser.add_argument("--observe", action="store_true",
                        help="record a failing baseline as OBSERVED and return zero")
    args = parser.parse_args()
    if (args.existing_report is None) != (args.existing_project is None):
        parser.error("--existing-report and --existing-project must be supplied together")
    for value in args.cli_arg:
        if value.split("=", 1)[0] in GATE_OWNED_FLAGS:
            parser.error(f"--cli-arg cannot override gate-owned option {value}")
    return args


def main() -> int:
    args = parse_args()
    try:
        binary = required_file(args.binary, "binary")
        metadata = required_file(args.metadata, "metadata")
        cli = required_file(args.cli, "CLI")
        inputs = {"binarySha256": file_hash(binary), "metadataSha256": file_hash(metadata)}
        with tempfile.TemporaryDirectory(prefix="il2cpprec-corpus-") as temporary:
            if args.existing_report:
                report_path = required_file(args.existing_report, "existing CLI report")
                project_dir = args.existing_project.resolve()
                if not project_dir.is_dir():
                    raise SetupError(f"existing project directory is missing: {project_dir}")
            else:
                project_dir = Path(temporary) / "project"
                report_path = Path(temporary) / "report.json"
                command = [str(cli), "--binary", str(binary), "--metadata", str(metadata),
                           "--include-images", args.image, "--output-dir", str(project_dir),
                           "--report", str(report_path), "--verify", *args.cli_arg]
                with (Path(temporary) / "cli.log").open("w") as log:
                    run = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=1800)
                if run.returncode not in (0, 1) or not report_path.is_file():
                    raise RuntimeError(f"CLI exited {run.returncode} without a valid report")
            cli_report = json.loads(report_path.read_text(encoding="utf-8"))
            if args.existing_report:
                paths = cli_report.get("outputPaths", {})
                for key, expected in (("binary", inputs["binarySha256"]),
                                      ("metadata", inputs["metadataSha256"])):
                    source = Path(paths.get(key, ""))
                    if not source.is_file() or file_hash(source) != expected:
                        raise SetupError(f"existing report {key} does not match supplied input")
                if Path(paths.get("outputDirectory", "")).resolve() != project_dir:
                    raise SetupError("existing project directory does not match CLI report outputDirectory")
            summary = summarize_cli(cli_report, args.image)
            summary.update({"schemaVersion": 1, "runner": "il2cpprec-corpus-gate",
                            "input": inputs, "cliArguments": args.cli_arg,
                            "cliOptions": cli_report.get("options", {}),
                            "projectSha256": project_digest(project_dir)})
            summary["compiler"] = compiler_result(project_dir)
            summary["oracle"] = oracle_result(args.oracle_script, cli)
            failures = []
            if summary["targetImage"]["errors"]:
                failures.append("target image has native recovery errors")
            if summary["compiler"]["status"] != "PASS":
                failures.append("generated C# project does not compile")
            if summary["oracle"]["status"] == "FAIL":
                failures.append("private oracle failed")
            if args.baseline:
                baseline = json.loads(required_file(args.baseline, "baseline").read_text(encoding="utf-8"))
                summary["delta"] = compare_baseline(baseline, summary)
                if summary["delta"]["csharpDelta"]["supported"] < 0:
                    failures.append("supported C# method count regressed")
                if summary["delta"]["nativeExactDelta"] < 0:
                    failures.append("native-exact method count regressed")
                if summary["delta"]["compilerErrorDelta"] > 0:
                    failures.append("compiler error count increased")
            summary["issues"] = failures
            summary["status"] = gate_status(failures, args.observe)
        encoded = json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
        return 0 if summary["status"] in ("PASS", "OBSERVED") else 1
    except (SetupError, OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(f"SETUP ERROR: {error}", file=sys.stderr)
        return 2
    except RuntimeError as error:
        print(f"GATE ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
