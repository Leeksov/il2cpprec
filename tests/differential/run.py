#!/usr/bin/env python3
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

TEST_DIR = Path(__file__).resolve().parent
ROOT = TEST_DIR.parents[1]
FIXTURE_DIR = TEST_DIR / "fixtures"
SUPPORT_DIR = TEST_DIR / "support"
ADDRESS = "0x1000"
UNSUPPORTED_RE = re.compile(
    r"RuntimeCalls_Unsupported_[A-Za-z0-9_]+|RuntimeCalls\.Unsupported[A-Za-z0-9_]*\s*\("
)


@dataclass(frozen=True)
class Fixture:
    name: str
    arch: str
    file: str
    behavior: str
    fidelity: str = "exact"
    arm32_mode: str = "arm"


@dataclass
class Recovery:
    fixture: Fixture
    source: str = ""
    error: str = ""


@dataclass(frozen=True)
class ManagedRuntime:
    kind: str
    compiler: str
    runner: str
    target_framework: str = ""


FIXTURES = [
    Fixture("SignedDivArm32", "arm32", "arm32_signed_div.bin", "signed"),
    Fixture("LoopSumArm32", "arm32", "arm32_loop_sum.bin", "loop"),
    Fixture("MemoryAddArm32", "arm32", "arm32_memory_add.bin", "memory"),
    Fixture("FloatAddArm32", "arm32", "arm32_float_vadd.bin", "float"),
    Fixture("ThumbAddSubArm32", "arm32", "arm32_thumb_add_sub.bin", "thumb_add_sub", arm32_mode="thumb"),
    Fixture("SignedDivArm64", "arm64", "arm64_signed_div.bin", "signed"),
    Fixture("LoopSumArm64", "arm64", "arm64_loop_sum.bin", "loop"),
    Fixture("MemoryAddArm64", "arm64", "arm64_memory_add.bin", "memory"),
    Fixture("FloatAddArm64", "arm64", "arm64_float_add.bin", "float"),
    Fixture("UnsupportedYieldArm64", "arm64", "arm64_unsupported_yield.bin", "unsupported", "partial"),
    Fixture("SignedDivX86", "x86", "x86_signed_div.bin", "signed"),
    Fixture("LoopSumX86", "x86", "x86_loop_sum.bin", "loop"),
    Fixture("MemoryAddX86", "x86", "x86_memory_add.bin", "memory"),
    Fixture("FloatAddX86", "x86", "x86_float_add.bin", "float"),
    Fixture("UnsupportedUd2X86", "x86", "x86_unsupported_ud2.bin", "unsupported", "partial"),
    Fixture("SignedDivX64", "x64", "x64_signed_div.bin", "signed"),
    Fixture("LoopSumX64", "x64", "x64_loop_sum.bin", "loop"),
    Fixture("MemoryAddX64", "x64", "x64_memory_add.bin", "memory"),
    Fixture("FloatAddX64", "x64", "x64_float_add.bin", "float"),
    Fixture("UnsupportedUd2X64", "x64", "x64_unsupported_ud2.bin", "unsupported", "partial"),
]

SIGNED_VECTORS = [
    (0, 5),
    (100, 5),
    (0xFFFFFF9C, 5),
    (100, 0xFFFFFFFB),
    (0xFFFFFF9C, 0xFFFFFFFB),
    (0x7FFFFFFF, 1),
]
FLOAT_VECTORS = [
    (0, 0),
    (3, 4),
    (0xFFFFFFF9, 2),
    (100, 0xFFFFFFFB),
    (16777217, 1),
]
THUMB_VECTORS = [
    (0, 0),
    (3, 4),
    (0xFFFFFFFF, 2),
    (0x80000000, 0x80000000),
    (100, 0xFFFFFFFB),
]
LOOP_VECTORS = [0, 1, 2, 5, 17]
MEMORY_VECTORS = [
    (0, 0),
    (10, 5),
    (0xFFFFFFFF, 2),
    (0x80000000, 0x80000000),
]
ARGUMENT_COUNTS = {"arm32": 4, "arm64": 8, "x86": 2, "x64": 4}
NATIVE_TYPES = {"arm32": "UInt32", "arm64": "UInt64", "x86": "UInt32", "x64": "UInt64"}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Recover machine-code fixtures to C#, execute them, and compare with managed oracles."
    )
    parser.add_argument("--cli", help="Path to il2cpprec_cli (or set IL2CPPREC_CLI).")
    parser.add_argument(
        "--runtime",
        choices=("auto", "dotnet", "mcs", "none"),
        default="auto",
        help="Managed compiler/runtime selection; 'none' exercises SKIP handling.",
    )
    parser.add_argument("--keep", action="store_true", help="Keep generated sources and build outputs.")
    parser.add_argument("--filter", help="Run only fixtures whose names contain this substring.")
    return parser.parse_args()


def find_cli(value):
    candidates = []
    if value:
        candidates.append(Path(value))
    elif os.environ.get("IL2CPPREC_CLI"):
        candidates.append(Path(os.environ["IL2CPPREC_CLI"]))
    else:
        executable = "il2cpprec_cli.exe" if os.name == "nt" else "il2cpprec_cli"
        candidates.extend(
            [
                ROOT / "build" / executable,
                ROOT / "build" / "Release" / executable,
                ROOT / "build" / "Debug" / executable,
            ]
        )
    for candidate in candidates:
        candidate = candidate.expanduser().resolve()
        if candidate.is_file():
            return candidate
    raise RuntimeError("il2cpprec_cli not found; build it or pass --cli PATH.")


def invoke(command, timeout):
    return subprocess.run(
        [str(part) for part in command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=timeout,
    )


def dotnet_runtime():
    dotnet = shutil.which("dotnet")
    if not dotnet:
        return None
    try:
        result = invoke([dotnet, "--list-sdks"], 20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    versions = []
    for line in result.stdout.splitlines():
        match = re.match(r"^(\d+)\.(\d+)\.(\d+)", line.strip())
        if match:
            versions.append(tuple(int(part) for part in match.groups()))
    if not versions:
        return None
    latest = max(versions)
    return ManagedRuntime("dotnet", dotnet, dotnet, "net{0}.0".format(latest[0]))


def mcs_runtime():
    mcs = shutil.which("mcs")
    mono = shutil.which("mono")
    if not mcs or not mono:
        return None
    return ManagedRuntime("mcs", mcs, mono)


def select_runtime(requested):
    if requested == "none":
        return None, "runtime disabled by --runtime none"
    if requested == "dotnet":
        runtime = dotnet_runtime()
        return runtime, "dotnet SDK not found"
    if requested == "mcs":
        runtime = mcs_runtime()
        return runtime, "mcs and mono not found together"
    runtime = dotnet_runtime()
    if runtime:
        return runtime, ""
    runtime = mcs_runtime()
    if runtime:
        return runtime, ""
    return None, "no usable dotnet SDK or mcs+mono pair found"


def cmake_cache_value(name):
    cache = ROOT / "build" / "CMakeCache.txt"
    if not cache.is_file():
        return ""
    prefix = name + ":"
    for line in cache.read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix) and "=" in line:
            return line.split("=", 1)[1]
    return ""


def build_thumb_driver(work_path):
    output = work_path / "RecoverThumb"
    if output.is_file():
        return output
    compiler = cmake_cache_value("CMAKE_CXX_COMPILER") or shutil.which("c++")
    library = ROOT / "build" / "libil2cpprec.a"
    capstone = cmake_cache_value("CAPSTONE_LIBRARY")
    if not compiler or not library.is_file() or not capstone:
        raise RuntimeError("Thumb recovery requires the configured C++ compiler, libil2cpprec.a, and Capstone")
    result = invoke(
        [
            compiler,
            "-std=c++20",
            "-I" + str(ROOT / "include"),
            SUPPORT_DIR / "RecoverThumb.cpp",
            library,
            capstone,
            "-o",
            output,
        ],
        120,
    )
    if result.returncode != 0:
        raise RuntimeError("Thumb driver build failed: " + process_details(result))
    return output


def recover_fixture(cli, fixture, work_path):
    path = FIXTURE_DIR / fixture.file
    if not path.is_file():
        return Recovery(fixture, error="missing fixture file: {0}".format(path))
    if fixture.arm32_mode == "thumb":
        try:
            thumb_driver = build_thumb_driver(work_path)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            return Recovery(fixture, error=str(error))
        command = [thumb_driver, path, fixture.name]
    else:
        command = [
            cli,
            "--arch",
            fixture.arch,
            "--address",
            ADDRESS,
            "--name",
            fixture.name,
            "--input",
            path,
        ]
    try:
        result = invoke(command, 30)
    except (OSError, subprocess.TimeoutExpired) as error:
        return Recovery(fixture, error="recovery failed to execute: {0}".format(error))
    if result.returncode != 0:
        return Recovery(
            fixture,
            error="recovery exited {0}: {1}".format(result.returncode, result.stderr.strip()),
        )
    expected_declaration = "public static class RecoveredMethods_" + fixture.name
    if expected_declaration not in result.stdout:
        return Recovery(fixture, error="generated C# does not contain " + expected_declaration)
    return Recovery(fixture, source=result.stdout)


def unsupported_markers(source):
    return sorted(set(match.group(0).rstrip(" (") for match in UNSUPPORTED_RE.finditer(source)))


def literal(value, arch):
    return "{0}{1}".format(value, "UL" if arch in ("arm64", "x64") else "U")


def recovered_call(fixture, values):
    arguments = list(values) + [0] * (ARGUMENT_COUNTS[fixture.arch] - len(values))
    rendered = ", ".join(literal(value, fixture.arch) for value in arguments)
    return "RecoveredMethods_{0}.{0}({1})".format(fixture.name, rendered)


def vector_label(values):
    return "_".join("{0:08X}".format(value) for value in values)


def generate_program(fixture):
    lines = []
    if fixture.behavior == "memory":
        for left, delta in MEMORY_VECTORS:
            label = vector_label((left, delta))
            call = recovered_call(fixture, (0, 0, delta) if fixture.arch in ("arm32", "arm64") else (0, delta))
            lines.extend(
                [
                    "        RuntimeMemory.Reset(16);",
                    "        RuntimeMemory.Fill(0xA5);",
                    "        RuntimeMemory.WriteU32(0, {0}U);".format(left),
                    "        byte[] expected_{0} = Oracle.MemoryBuffer({1}U, {2}U);".format(label, left, delta),
                    "        ulong actual_{0} = (ulong){1};".format(label, call),
                    "        Check(\"{0}:return\", actual_{0}, unchecked((ulong)unchecked({1}U + {2}U)));".format(
                        label, left, delta
                    ),
                    "        CheckBuffer(\"{0}:buffer\", RuntimeMemory.Snapshot(), expected_{0});".format(label),
                ]
            )
    else:
        if fixture.behavior == "signed":
            vectors = SIGNED_VECTORS
            oracle = "SignedDiv"
        elif fixture.behavior == "float":
            vectors = FLOAT_VECTORS
            oracle = "FloatAdd"
        elif fixture.behavior == "thumb_add_sub":
            vectors = THUMB_VECTORS
            oracle = "ThumbAddSub"
        elif fixture.behavior == "loop":
            vectors = [(value,) for value in LOOP_VECTORS]
            oracle = "LoopSum"
        else:
            raise RuntimeError("exact fixture has no executable oracle: " + fixture.name)
        for values in vectors:
            label = vector_label(values)
            arguments = ", ".join("{0}U".format(value) for value in values)
            lines.append(
                "        Check(\"{0}\", (ulong){1}, Oracle.{2}({3}));".format(
                    label, recovered_call(fixture, values), oracle, arguments
                )
            )
    body = "\n".join(lines)
    return """using System;

public static class Program
{
    private static int checks;
    private static int failures;

    private static void Check(string label, ulong actual, ulong expected)
    {
        ++checks;
        if (actual == expected)
            return;
        ++failures;
        Console.WriteLine("MISMATCH " + label + ": actual=0x" + actual.ToString("X") + " expected=0x" + expected.ToString("X"));
    }

    private static void CheckBuffer(string label, byte[] actual, byte[] expected)
    {
        ++checks;
        if (actual.Length == expected.Length)
        {
            int difference = -1;
            for (int i = 0; i < actual.Length; ++i)
            {
                if (actual[i] != expected[i])
                {
                    difference = i;
                    break;
                }
            }
            if (difference < 0)
                return;
            ++failures;
            Console.WriteLine("MISMATCH " + label + " at byte " + difference + ": actual=0x" + actual[difference].ToString("X2") + " expected=0x" + expected[difference].ToString("X2"));
            return;
        }
        ++failures;
        Console.WriteLine("MISMATCH " + label + ": actual length=" + actual.Length + " expected length=" + expected.Length);
    }

    public static int Main()
    {
__BODY__
        if (failures == 0)
            Console.WriteLine("OK " + checks + " comparisons");
        return failures == 0 ? 0 : 1;
    }
}
""".replace("__BODY__", body)


def write_case_sources(directory, recovery):
    fixture = recovery.fixture
    directory.mkdir(parents=True)
    (directory / "Recovered.cs").write_text(recovery.source, encoding="utf-8")
    runtime = (SUPPORT_DIR / "RuntimeSupport.cs.in").read_text(encoding="utf-8")
    runtime = runtime.replace("__NATIVE_UINT__", NATIVE_TYPES[fixture.arch])
    (directory / "RuntimeSupport.cs").write_text(runtime, encoding="utf-8")
    shutil.copyfile(SUPPORT_DIR / "Oracle.cs", directory / "Oracle.cs")
    (directory / "Program.cs").write_text(generate_program(fixture), encoding="utf-8")


def process_details(result):
    details = []
    if result.stdout.strip():
        details.append("stdout:\n" + result.stdout.strip())
    if result.stderr.strip():
        details.append("stderr:\n" + result.stderr.strip())
    text = "\n".join(details)
    if len(text) > 12000:
        text = text[:12000] + "\n... output truncated ..."
    return text


def execute_dotnet(runtime, directory, name):
    project = directory / (name + ".csproj")
    project.write_text(
        """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>{0}</TargetFramework>
    <AssemblyName>{1}</AssemblyName>
    <LangVersion>latest</LangVersion>
    <ImplicitUsings>disable</ImplicitUsings>
    <Nullable>disable</Nullable>
  </PropertyGroup>
</Project>
""".format(runtime.target_framework, name),
        encoding="utf-8",
    )
    build = invoke(
        [
            runtime.compiler,
            "build",
            project,
            "--configuration",
            "Release",
            "--nologo",
            "--verbosity",
            "quiet",
        ],
        120,
    )
    if build.returncode != 0:
        return "compile", build
    binary = directory / "bin" / "Release" / runtime.target_framework / (name + ".dll")
    return "execute", invoke([runtime.runner, binary], 30)


def execute_mcs(runtime, directory, name):
    binary = directory / (name + ".exe")
    sources = [directory / "RuntimeSupport.cs", directory / "Oracle.cs", directory / "Recovered.cs", directory / "Program.cs"]
    build = invoke([runtime.compiler, "-optimize+", "-langversion:latest", "-out:" + str(binary)] + sources, 120)
    if build.returncode != 0:
        return "compile", build
    return "execute", invoke([runtime.runner, binary], 30)


def print_process_failure(fixture, phase, result):
    print("FAIL {0}/{1}: {2} exited {3}".format(fixture.arch, fixture.name, phase, result.returncode))
    details = process_details(result)
    if details:
        print(details)


def main():
    args = parse_args()
    selected = [fixture for fixture in FIXTURES if not args.filter or args.filter in fixture.name]
    if not selected:
        print("No fixtures match --filter {0!r}.".format(args.filter), file=sys.stderr)
        return 2
    try:
        cli = find_cli(args.cli)
    except RuntimeError as error:
        print("ERROR: " + str(error), file=sys.stderr)
        return 2

    work = tempfile.mkdtemp(prefix="il2cpprec-differential-", dir=str(TEST_DIR) if args.keep else None)
    work_path = Path(work)
    failures = 0
    passed = 0
    partial = 0
    skipped = 0
    recoveries = []
    try:
        for fixture in selected:
            recovery = recover_fixture(cli, fixture, work_path)
            recoveries.append(recovery)
            if recovery.error:
                print("FAIL {0}/{1}: {2}".format(fixture.arch, fixture.name, recovery.error))
                failures += 1

        runtime, unavailable_reason = select_runtime(args.runtime)
        for recovery in recoveries:
            fixture = recovery.fixture
            if recovery.error:
                continue
            markers = unsupported_markers(recovery.source)
            if fixture.fidelity == "partial":
                if not markers:
                    print("FAIL {0}/{1}: declared partial but no unsupported operation was emitted".format(fixture.arch, fixture.name))
                    failures += 1
                else:
                    print("PARTIAL {0}/{1}: {2}".format(fixture.arch, fixture.name, ", ".join(markers)))
                    partial += 1
                continue
            if runtime is None:
                print("SKIP {0}/{1}: {2}".format(fixture.arch, fixture.name, unavailable_reason))
                skipped += 1
                continue
            if markers:
                print(
                    "FAIL {0}/{1}: exact recovery emitted unsupported operations: {2}".format(
                        fixture.arch, fixture.name, ", ".join(markers)
                    )
                )
                failures += 1
                continue

            case_directory = work_path / fixture.arch / fixture.name
            write_case_sources(case_directory, recovery)
            try:
                if runtime.kind == "dotnet":
                    phase, result = execute_dotnet(runtime, case_directory, fixture.name)
                else:
                    phase, result = execute_mcs(runtime, case_directory, fixture.name)
            except (OSError, subprocess.TimeoutExpired) as error:
                print("FAIL {0}/{1}: managed {2}: {3}".format(fixture.arch, fixture.name, runtime.kind, error))
                failures += 1
                continue
            if phase == "compile" and result.returncode != 0:
                print_process_failure(fixture, phase, result)
                failures += 1
            elif result.returncode != 0:
                print_process_failure(fixture, phase, result)
                failures += 1
            else:
                vector_count = len(MEMORY_VECTORS) * 2 if fixture.behavior == "memory" else {
                    "signed": len(SIGNED_VECTORS),
                    "float": len(FLOAT_VECTORS),
                    "thumb_add_sub": len(THUMB_VECTORS),
                    "loop": len(LOOP_VECTORS),
                }[fixture.behavior]
                print("PASS exact {0}/{1}: {2} comparisons".format(fixture.arch, fixture.name, vector_count))
                passed += 1
    finally:
        if args.keep:
            print("Generated files: " + str(work_path))
        else:
            shutil.rmtree(work, ignore_errors=True)

    print(
        "SUMMARY passed={0} partial={1} skipped={2} failed={3}".format(
            passed, partial, skipped, failures
        )
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
