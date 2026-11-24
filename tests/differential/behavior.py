#!/usr/bin/env python3
import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import run as differential

TEST_DIR = Path(__file__).resolve().parent
ROOT = TEST_DIR.parents[1]
SUPPORT_DIR = TEST_DIR / "support"


def parse_args():
    parser = argparse.ArgumentParser(description="Exercise managed-pattern analysis and generated runtime behaviors.")
    parser.add_argument(
        "--runtime",
        choices=("auto", "dotnet", "mcs", "none"),
        default="auto",
        help="Managed compiler/runtime selection; 'none' exercises SKIP handling.",
    )
    parser.add_argument("--keep", action="store_true", help="Keep generated sources and build outputs.")
    return parser.parse_args()


def build_native_driver(work_path):
    compiler = differential.cmake_cache_value("CMAKE_CXX_COMPILER") or shutil.which("c++")
    library = ROOT / "build" / "libil2cpprec.a"
    capstone = differential.cmake_cache_value("CAPSTONE_LIBRARY")
    if not compiler or not library.is_file() or not capstone:
        raise RuntimeError("behavior tests require the configured C++ compiler, libil2cpprec.a, and Capstone")
    output = work_path / "NativeBehaviors"
    result = differential.invoke(
        [
            compiler,
            "-std=c++20",
            "-O3",
            "-DNDEBUG",
            "-I" + str(ROOT / "include"),
            SUPPORT_DIR / "NativeBehaviors.cpp",
            library,
            capstone,
            "-o",
            output,
        ],
        120,
    )
    if result.returncode != 0:
        raise RuntimeError("native behavior driver build failed:\n" + differential.process_details(result))
    return output


def execute_dotnet(runtime, directory):
    name = "ManagedBehaviors"
    project = directory / (name + ".csproj")
    project.write_text(
        """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>{0}</TargetFramework>
    <AssemblyName>{1}</AssemblyName>
    <LangVersion>latest</LangVersion>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    <ImplicitUsings>disable</ImplicitUsings>
    <Nullable>disable</Nullable>
  </PropertyGroup>
</Project>
""".format(runtime.target_framework, name),
        encoding="utf-8",
    )
    build = differential.invoke(
        [runtime.compiler, "build", project, "--configuration", "Release", "--nologo", "--verbosity", "quiet"],
        120,
    )
    if build.returncode != 0:
        return "compile", build
    binary = directory / "bin" / "Release" / runtime.target_framework / (name + ".dll")
    return "execute", differential.invoke([runtime.runner, binary], 30)


def execute_mcs(runtime, directory):
    binary = directory / "ManagedBehaviors.exe"
    build = differential.invoke(
        [
            runtime.compiler,
            "-unsafe",
            "-optimize+",
            "-langversion:latest",
            "-out:" + str(binary),
            directory / "RuntimeSupport.cs",
            directory / "RuntimeBehaviors.cs",
        ],
        120,
    )
    if build.returncode != 0:
        return "compile", build
    return "execute", differential.invoke([runtime.runner, binary], 30)


def print_output(result):
    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    if result.stderr:
        print(result.stderr, end="" if result.stderr.endswith("\n") else "\n", file=sys.stderr)


def main():
    args = parse_args()
    work = tempfile.mkdtemp(prefix="il2cpprec-behaviors-", dir=str(TEST_DIR) if args.keep else None)
    work_path = Path(work)
    failed = False
    try:
        try:
            driver = build_native_driver(work_path)
            native = differential.invoke([driver], 120)
            print_output(native)
            failed = failed or native.returncode != 0
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            print("FAIL NativeBehaviors: " + str(error), file=sys.stderr)
            return 1

        runtime, unavailable_reason = differential.select_runtime(args.runtime)
        if runtime is None:
            print("SKIP ManagedRuntimeBehaviors: " + unavailable_reason)
            return 1 if failed else 0

        generated = differential.invoke([driver, "--runtime-support", work_path / "RuntimeSupport.cs"], 30)
        if generated.returncode != 0:
            print_output(generated)
            print("FAIL RuntimeSupportGenerator: exited {0}".format(generated.returncode), file=sys.stderr)
            return 1
        shutil.copyfile(SUPPORT_DIR / "RuntimeBehaviors.cs", work_path / "RuntimeBehaviors.cs")
        try:
            if runtime.kind == "dotnet":
                phase, managed = execute_dotnet(runtime, work_path)
            else:
                phase, managed = execute_mcs(runtime, work_path)
        except (OSError, subprocess.TimeoutExpired) as error:
            print("FAIL ManagedRuntimeBehaviors: " + str(error), file=sys.stderr)
            return 1
        if managed.returncode != 0 and runtime.kind == "mcs" and phase == "compile" and "CS0246" in managed.stderr and "unmanaged" in managed.stderr:
            print("SKIP ManagedRuntimeBehaviors: mcs cannot compile the generated C# unmanaged constraints")
            return 1 if failed else 0
        print_output(managed)
        if managed.returncode != 0:
            print("FAIL ManagedRuntimeBehaviors: {0} exited {1}".format(phase, managed.returncode), file=sys.stderr)
            failed = True
        return 1 if failed else 0
    finally:
        if args.keep:
            print("Generated files: " + str(work_path))
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
