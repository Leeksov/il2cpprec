#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from reporting import build_report, diff_reports, make_case, recovery_from_cli, signed
from synthetic import (
    ARCHITECTURES,
    INCLUDED_IMAGE,
    VERSIONS,
    Profile,
    SyntheticFixture,
    make_fixture,
    quality_methods,
    standard_methods,
)


TEST_DIR = Path(__file__).resolve().parent
ROOT = TEST_DIR.parents[1]
class ConfigurationError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run IL2CPP metadata version acceptance scenarios.")
    parser.add_argument("--cli", help="Path to il2cpprec_cli (or set IL2CPPREC_CLI).")
    parser.add_argument(
        "--suite",
        action="append",
        choices=("all", "matrix", "synthetic", "build", "criticalops"),
        help="Suite to run; may be repeated. Default: all.",
    )
    parser.add_argument("--profile", help="Run matrix profile IDs containing this substring.")
    parser.add_argument("--runtime", choices=("auto", "dotnet", "mcs", "none"), default="auto")
    parser.add_argument("--criticalops-binary", help="Real Critical Ops native binary fixture.")
    parser.add_argument("--criticalops-metadata", help="Real Critical Ops global-metadata.dat fixture.")
    parser.add_argument("--baseline", help="Previous runner JSON report used for exact/partial/errors diff.")
    parser.add_argument("--report", help="Write the current machine-readable JSON report.")
    parser.add_argument("--keep", action="store_true", help="Keep generated fixtures and build outputs.")
    parser.add_argument("--fail-on-skip", action="store_true", help="Return failure when any scenario is skipped.")
    return parser.parse_args()


def find_cli(value: str | None) -> Path:
    executable = "il2cpprec_cli.exe" if os.name == "nt" else "il2cpprec_cli"
    configured = value or os.environ.get("IL2CPPREC_CLI")
    candidates = [Path(configured)] if configured else [
        ROOT / "build" / executable,
        ROOT / "build" / "Release" / executable,
        ROOT / "build" / "Debug" / executable,
        ROOT / "build" / "macos-arm64" / executable,
    ]
    for candidate in candidates:
        candidate = candidate.expanduser().resolve()
        if candidate.is_file():
            return candidate
    raise ConfigurationError("il2cpprec_cli not found; build it or pass --cli PATH")


def invoke(command: list[Any], timeout: int = 180) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
    environment["DOTNET_SKIP_FIRST_TIME_EXPERIENCE"] = "1"
    return subprocess.run(
        [str(part) for part in command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        env=environment,
    )


def process_details(result: subprocess.CompletedProcess[str]) -> str:
    text = "\n".join(part for part in (result.stdout.strip(), result.stderr.strip()) if part)
    if len(text) > 12000:
        return text[:12000] + "\n... output truncated ..."
    return text


def load_cli_report(path: Path) -> dict[str, Any]:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"cannot read CLI JSON report {path}: {error}") from error
    if not isinstance(report, dict) or not isinstance(report.get("methods"), list):
        raise RuntimeError("CLI JSON report does not contain a method list")
    recovery = recovery_from_cli(report)
    if report.get("total") != sum(recovery.values()):
        raise RuntimeError("CLI JSON report total does not match exact/partial/errors")
    return report


def expected_method_status(fixture: SyntheticFixture) -> dict[str, str]:
    return {
        f"Acceptance.{method.type_name}__{method.name}": method.kind
        for method in fixture.methods
    }


def validate_methods(report: dict[str, Any], fixture: SyntheticFixture) -> None:
    expected = expected_method_status(fixture)
    actual = {
        method.get("name"): method.get("status")
        for method in report["methods"]
        if isinstance(method, dict)
    }
    if actual != expected:
        raise RuntimeError(f"resolved methods differ: expected {expected}, got {actual}")
    for method in report["methods"]:
        if method["status"] != "error" and (not method.get("address") or method.get("size", 0) <= 0):
            raise RuntimeError(f"resolved method has no native range: {method}")


def validate_profile(report: dict[str, Any], profile: Profile) -> dict[str, Any]:
    source = report.get("sourceProfile")
    if not isinstance(source, dict) or source.get("supported") is not True:
        raise RuntimeError(f"profile {profile.id} was not marked supported by CLI")
    expected_variant = {
        "24.1": "2017.4.11f1-metadata-24.1",
        "24.3": "24.2",
    }.get(profile.version, profile.version)
    if source.get("variant") != expected_variant:
        raise RuntimeError(
            f"profile {profile.id} selected variant {source.get('variant')!r}, expected {expected_variant!r}"
        )
    return {
        "requestedMetadataVersion": profile.version,
        "reportedVariant": source.get("variant"),
        "reportedUnityMetadataVersion": source.get("unityMetadataVersion"),
        "layoutHash": source.get("layoutHash"),
        "supported": True,
    }


def run_synthetic(
    cli: Path,
    work: Path,
    fixture: SyntheticFixture,
    case_id: str,
    suite: str,
    filtered_build: bool = False,
) -> dict[str, Any]:
    case_dir = work / case_id.replace("/", "_")
    binary, metadata = fixture.write(case_dir)
    report_path = case_dir / "recovery.json"
    output_dir = case_dir / "project"
    command = [
        cli,
        "--binary", binary,
        "--metadata", metadata,
        "--workers", "1",
        "--report", report_path,
    ]
    if filtered_build:
        command.extend(("--output-dir", output_dir, "--include-images", INCLUDED_IMAGE))
    try:
        result = invoke(command)
        report = load_cli_report(report_path)
        recovery = recovery_from_cli(report)
        profile = validate_profile(report, fixture.profile)
        validate_methods(report, fixture)
        expected = {
            key: sum(method.kind == key for method in fixture.methods)
            for key in ("exact", "partial", "errors")
        }
        expected["errors"] = sum(method.kind == "error" for method in fixture.methods)
        if recovery != expected:
            raise RuntimeError(f"recovery counts differ: expected {expected}, got {recovery}")
        expected_exit = 1 if expected["errors"] else 0
        if result.returncode != expected_exit:
            raise RuntimeError(f"CLI exited {result.returncode}, expected {expected_exit}: {process_details(result)}")
        return make_case(
            case_id,
            suite,
            "PASS",
            "provisional",
            "synthetic method resolution passed; native semantics are not verified",
            recovery,
            profile=profile,
            architecture=fixture.profile.architecture,
            methods=report["methods"],
            command=[str(part) for part in command],
            outputDirectory=str(output_dir) if filtered_build else None,
        )
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        recovery = recovery_from_cli(report) if "report" in locals() else None
        return make_case(
            case_id,
            suite,
            "FAIL",
            "provisional",
            str(error),
            recovery,
            architecture=fixture.profile.architecture,
            details=process_details(result) if "result" in locals() else "",
        )


def dotnet_sdk(requested: str) -> tuple[str | None, str]:
    if requested == "none":
        return None, "managed runtime disabled by --runtime none"
    if requested == "mcs":
        return None, "filtered SDK-style C# project build requires dotnet, not mcs"
    dotnet = shutil.which("dotnet")
    if not dotnet:
        return None, "dotnet SDK not found"
    try:
        result = invoke([dotnet, "--list-sdks"], 30)
    except (OSError, subprocess.TimeoutExpired) as error:
        return None, f"dotnet SDK discovery failed: {error}"
    if result.returncode != 0 or not result.stdout.strip():
        return None, "no usable dotnet SDK found"
    return dotnet, ""


def run_filtered_build(cli: Path, work: Path, requested_runtime: str) -> dict[str, Any]:
    case_id = "build/filtered-csharp"
    dotnet, unavailable = dotnet_sdk(requested_runtime)
    if dotnet is None:
        return make_case(case_id, "build", "SKIP", "unverified", unavailable)
    fixture = make_fixture("24.5", "x64")
    case = run_synthetic(cli, work, fixture, case_id, "build", filtered_build=True)
    if case["status"] != "PASS":
        return case
    output_dir = Path(case["outputDirectory"])
    try:
        projects = sorted(output_dir.glob("*.csproj"))
        if len(projects) != 1:
            raise RuntimeError(f"expected one generated C# project, found {len(projects)}")
        project = projects[0]
        root = ET.parse(project).getroot()
        compile_items = sorted(node.attrib["Include"] for node in root.iter("Compile"))
        if len(compile_items) < 2:
            raise RuntimeError(f"generated project has too few compile items: {compile_items}")
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in output_dir.rglob("*.cs")
            if "obj" not in path.parts and "bin" not in path.parts
        )
        if "IncludedMethod" not in sources:
            raise RuntimeError("filtered project omitted IncludedMethod")
        if "ExcludedMethod" in sources or "ExcludedType" in sources:
            raise RuntimeError("filtered project contains excluded image declarations")
        build = invoke([
            dotnet,
            "build",
            project,
            "--configuration",
            "Release",
            "--nologo",
            "--verbosity",
            "minimal",
        ])
        if build.returncode != 0:
            raise RuntimeError(f"filtered C# build exited {build.returncode}: {process_details(build)}")
        case["reason"] = "filtered generated C# project compiled; synthetic native semantics remain provisional"
        case["build"] = {
            "compiler": dotnet,
            "project": str(project),
            "compileItems": compile_items,
            "includedImage": INCLUDED_IMAGE,
        }
        case.pop("outputDirectory", None)
        return case
    except (OSError, RuntimeError, ET.ParseError, subprocess.TimeoutExpired) as error:
        case["status"] = "FAIL"
        case["reason"] = str(error)
        return case


def run_real_criticalops(cli: Path, work: Path, binary_value: str | None, metadata_value: str | None) -> dict[str, Any]:
    case_id = "criticalops/full-game"
    if not binary_value and not metadata_value:
        return make_case(
            case_id,
            "criticalops",
            "SKIP",
            "unverified",
            "real Critical Ops binary/metadata fixtures were not supplied; snippet regression does not prove full-game support",
        )
    if not binary_value or not metadata_value:
        return make_case(
            case_id,
            "criticalops",
            "FAIL",
            "unverified",
            "both --criticalops-binary and --criticalops-metadata are required",
        )
    binary = Path(binary_value).expanduser().resolve()
    metadata = Path(metadata_value).expanduser().resolve()
    if not binary.is_file() or not metadata.is_file():
        return make_case(
            case_id,
            "criticalops",
            "SKIP",
            "unverified",
            f"real Critical Ops fixture is missing: binary={binary}, metadata={metadata}",
        )
    report_path = work / "criticalops-full.json"
    command = [
        cli,
        "--binary", binary,
        "--metadata", metadata,
        "--game", "criticalops",
        "--report", report_path,
    ]
    try:
        result = invoke(command, 300)
        report = load_cli_report(report_path)
        recovery = recovery_from_cli(report)
        expected_exit = 1 if recovery["errors"] else 0
        if result.returncode != expected_exit:
            raise RuntimeError(f"CLI exited {result.returncode}, expected {expected_exit}: {process_details(result)}")
        if report["total"] == 0:
            raise RuntimeError("real Critical Ops fixture resolved zero methods")
        return make_case(
            case_id,
            "criticalops",
            "PASS",
            "provisional",
            "real fixture was recovered and counted, but no independent native verification establishes support",
            recovery,
            sourceProfile=report.get("sourceProfile"),
            registration={
                "genericMethodCount": report.get("genericMethodCount"),
                "invokerCount": report.get("invokerCount"),
                "metadataUsageCount": report.get("metadataUsageCount"),
                "reasons": report.get("registrationReasons"),
            },
            methods=report["methods"],
        )
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        return make_case(
            case_id,
            "criticalops",
            "FAIL",
            "provisional",
            str(error),
            details=process_details(result) if "result" in locals() else "",
        )


def load_baseline(value: str | None) -> dict[str, Any] | None:
    if not value:
        return None
    path = Path(value).expanduser().resolve()
    try:
        baseline = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ConfigurationError(f"cannot read baseline {path}: {error}") from error
    if not isinstance(baseline, dict):
        raise ConfigurationError("baseline JSON root must be an object")
    return baseline


def print_case(case: dict[str, Any]) -> None:
    recovery = case["recovery"]
    print(
        f"{case['status']} {case['id']} [{case['verification']}] "
        f"exact={recovery['exact']} partial={recovery['partial']} errors={recovery['errors']}: {case['reason']}"
    )
    if case["status"] == "FAIL" and case.get("details"):
        print(case["details"])


def main() -> int:
    args = parse_args()
    try:
        cli = find_cli(args.cli)
        baseline = load_baseline(args.baseline)
    except ConfigurationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2

    suites = set(args.suite or ("all",))
    if "all" in suites:
        suites = {"matrix", "synthetic", "build", "criticalops"}
    profiles = [Profile(version, architecture) for version in VERSIONS for architecture in ARCHITECTURES]
    if args.profile:
        profiles = [profile for profile in profiles if args.profile in profile.id]
        if not profiles:
            print(f"ERROR: no profiles match {args.profile!r}", file=sys.stderr)
            return 2

    if args.keep:
        work = Path(tempfile.mkdtemp(prefix=".acceptance-", dir=TEST_DIR))
    else:
        work = Path(tempfile.mkdtemp(prefix="il2cpprec-acceptance-"))
    cases: list[dict[str, Any]] = []
    try:
        if "matrix" in suites:
            for profile in profiles:
                cases.append(run_synthetic(
                    cli,
                    work,
                    make_fixture(profile.version, profile.architecture),
                    f"profile/{profile.id}",
                    "matrix",
                ))
        if "synthetic" in suites:
            cases.append(run_synthetic(
                cli,
                work,
                make_fixture("24.5", "x64", quality=True),
                "synthetic/method-resolution",
                "synthetic",
            ))
        if "build" in suites:
            cases.append(run_filtered_build(cli, work, args.runtime))
        if "criticalops" in suites:
            cases.append(run_real_criticalops(
                cli, work, args.criticalops_binary, args.criticalops_metadata
            ))

        report = build_report(cases, str(cli))
        if baseline is not None:
            try:
                report["diff"] = diff_reports(baseline, report)
            except (KeyError, TypeError, ValueError) as error:
                print(f"ERROR: invalid baseline: {error}", file=sys.stderr)
                return 2
        for case in cases:
            print_case(case)
        totals = report["totals"]
        recovery = report["recovery"]
        print(
            "ACCEPTANCE SUMMARY "
            f"passed={totals['passed']} failed={totals['failed']} skipped={totals['skipped']} "
            f"provisional={totals['provisional']} native-verified={totals['nativeVerified']} "
            f"exact={recovery['exact']} partial={recovery['partial']} errors={recovery['errors']}"
        )
        if "diff" in report:
            delta = report["diff"]["delta"]
            print(
                "DIFF "
                f"exact={signed(delta['exact'])} partial={signed(delta['partial'])} errors={signed(delta['errors'])}"
            )
            for change in report["diff"]["cases"]:
                case_delta = change["delta"]
                print(
                    f"DIFF {change['id']} {change['beforeStatus']}->{change['afterStatus']} "
                    f"exact={signed(case_delta['exact'])} partial={signed(case_delta['partial'])} "
                    f"errors={signed(case_delta['errors'])}"
                )
        if args.report:
            report_path = Path(args.report).expanduser().resolve()
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"REPORT {report_path}")
        if args.keep:
            print(f"WORK {work}")
        if totals["failed"] or (args.fail_on_skip and totals["skipped"]):
            return 1
        return 0
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
