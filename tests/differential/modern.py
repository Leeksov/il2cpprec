#!/usr/bin/env python3
"""Synthetic modern metadata probes and an independent native/C# FP oracle."""

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import run as differential

TEST_DIR = Path(__file__).resolve().parent
ROOT = TEST_DIR.parents[1]
SUPPORT_DIR = TEST_DIR / "support"
ORACLE_KEYS = ("float_add", "float_sqrt", "vector_add_0", "vector_add_1", "vector_add_2", "vector_add_3")
SUMMARY = re.compile(r"MODERN_NATIVE SUMMARY passed=(\d+) partial=(\d+) provisional=(\d+) failed=(\d+)")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", choices=("auto", "dotnet", "mcs", "none"), default="auto")
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build",
                        help="CMake build directory containing libil2cpprec.a")
    parser.add_argument("--cli", type=Path, help="CLI for the optional ARM32 NEON recovery probe")
    parser.add_argument("--keep", action="store_true")
    return parser.parse_args()


def cache_value(build_dir, name):
    cache = build_dir / "CMakeCache.txt"
    if not cache.is_file():
        return ""
    for line in cache.read_text(encoding="utf-8").splitlines():
        if line.startswith(name + ":") and "=" in line:
            return line.split("=", 1)[1]
    return ""


def build_driver(work, build_dir):
    compiler = cache_value(build_dir, "CMAKE_CXX_COMPILER") or shutil.which("c++")
    library = build_dir / "libil2cpprec.a"
    capstone = cache_value(build_dir, "CAPSTONE_LIBRARY")
    if not compiler or not library.is_file() or not capstone:
        raise RuntimeError("modern probes require the configured C++ compiler, libil2cpprec.a, and Capstone")
    output = work / "ModernBehaviors"
    result = differential.invoke([
        compiler, "-std=c++20", "-O2", "-I" + str(ROOT / "include"),
        SUPPORT_DIR / "ModernBehaviors.cpp", library, capstone, "-o", output,
    ], 120)
    if result.returncode:
        raise RuntimeError("modern driver build failed:\n" + differential.process_details(result))
    return output


def native_oracle(driver):
    result = differential.invoke([driver, "--runtime-oracle"], 30)
    if result.returncode:
        raise RuntimeError("native oracle failed:\n" + differential.process_details(result))
    values = {}
    for line in result.stdout.splitlines():
        match = re.fullmatch(r"([a-z0-9_]+)=(0x[0-9a-fA-F]{1,8})", line)
        if not match or match.group(1) in values:
            raise RuntimeError("malformed or duplicate native oracle value: " + line)
        values[match.group(1)] = match.group(2)
    if set(values) != set(ORACLE_KEYS):
        raise RuntimeError("native oracle keys differ from the six required FP/vector values")
    return values


def managed_oracle(runtime, work, values):
    source = SUPPORT_DIR / "ModernOracle.cs"
    if runtime.kind == "dotnet":
        project = work / "ModernOracle.csproj"
        project.write_text(
            '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType>'
            '<TargetFramework>{}</TargetFramework><EnableDefaultCompileItems>false</EnableDefaultCompileItems>'
            '</PropertyGroup><ItemGroup><Compile Include="{}" /></ItemGroup></Project>'.format(
                runtime.target_framework, source), encoding="utf-8")
        build = differential.invoke([runtime.compiler, "build", project, "--configuration", "Release",
                                     "--nologo", "--verbosity", "quiet"], 120)
        binary = work / "bin" / "Release" / runtime.target_framework / "ModernOracle.dll"
        command = [runtime.runner, binary]
    else:
        binary = work / "ModernOracle.exe"
        build = differential.invoke([runtime.compiler, "-out:" + str(binary), source], 120)
        command = [runtime.runner, binary]
    if build.returncode:
        raise RuntimeError("managed oracle compile failed:\n" + differential.process_details(build))
    result = differential.invoke(command + [values[key] for key in ORACLE_KEYS], 30)
    print(result.stdout, end="")
    if result.returncode or "MODERN_ORACLE SUMMARY comparisons=6 failed=0" not in result.stdout:
        raise RuntimeError("managed oracle failed:\n" + differential.process_details(result))


def arm32_probe(cli, runtime, work):
    if not cli.is_file():
        print("PROVISIONAL Arm32NeonLane: CLI unavailable for recovery and execution")
        return "provisional"
    fixture = differential.Fixture("Arm32NeonLane", "arm32", "arm32_neon_lane.bin", "modern_neon")
    recovery = differential.recover_fixture(cli, fixture, work)
    if recovery.error:
        raise RuntimeError("ARM32 NEON recovery failed: " + recovery.error)
    markers = differential.unsupported_markers(recovery.source)
    if markers:
        print("PARTIAL Arm32NeonLane: " + ", ".join(markers))
        return "partial"
    if runtime is None:
        print("PROVISIONAL Arm32NeonLane: recovered source requires C# execution")
        return "provisional"
    case = work / "arm32-neon"
    case.mkdir()
    (case / "Recovered.cs").write_text(recovery.source, encoding="utf-8")
    support = (SUPPORT_DIR / "RuntimeSupport.cs.in").read_text(encoding="utf-8")
    (case / "RuntimeSupport.cs").write_text(support.replace("__NATIVE_UINT__", "UInt32"), encoding="utf-8")
    (case / "Oracle.cs").write_text("public static class Oracle {}\n", encoding="utf-8")
    (case / "Program.cs").write_text("""using System;
public static class Program {
    public static int Main() {
        foreach (uint value in new uint[] {0, 1, 0x7f, 0xff}) {
            uint expected = (value + 0x12U) & 0xffU;
            uint actual = (uint)RecoveredMethods_Arm32NeonLane.Arm32NeonLane(value, 0, 0, 0);
            if (actual != expected) {
                Console.WriteLine("FAIL Arm32NeonLane input=" + value + " actual=" + actual + " expected=" + expected);
                return 1;
            }
        }
        Console.WriteLine("PASS executed Arm32NeonLane comparisons=4");
        return 0;
    }
}
""", encoding="utf-8")
    if runtime.kind == "dotnet":
        phase, result = differential.execute_dotnet(runtime, case, "Arm32NeonLane")
    else:
        phase, result = differential.execute_mcs(runtime, case, "Arm32NeonLane")
    if result.returncode:
        raise RuntimeError("ARM32 NEON C# {} failed:\n{}".format(phase, differential.process_details(result)))
    print(result.stdout, end="")
    return "executed"


def main():
    args = parse_args()
    work = Path(tempfile.mkdtemp(prefix="il2cpprec-modern-", dir=str(TEST_DIR) if args.keep else None))
    try:
        build_dir = args.build_dir.expanduser().resolve()
        driver = build_driver(work, build_dir)
        native = differential.invoke([driver], 120)
        print(native.stdout, end="")
        if native.stderr:
            print(native.stderr, file=sys.stderr, end="")
        match = SUMMARY.search(native.stdout)
        if native.returncode or not match or int(match.group(4)):
            raise RuntimeError("modern native probes failed")
        values = native_oracle(driver)
        runtime, reason = differential.select_runtime(args.runtime)
        if runtime is None:
            print("SKIP ModernOracle: " + reason)
        else:
            managed_oracle(runtime, work, values)
        cli = args.cli.expanduser().resolve() if args.cli else build_dir / "il2cpprec_cli"
        arm32 = arm32_probe(cli, runtime, work)
        print("MODERN SUMMARY synthetic={} expected_partial={} provisional={} oracle={} arm32={}".format(
            match.group(1), match.group(2), match.group(3), "skipped" if runtime is None else "passed", arm32))
        return 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print("FAIL ModernBehaviors: " + str(error), file=sys.stderr)
        return 1
    finally:
        if args.keep:
            print("Generated files: " + str(work))
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
