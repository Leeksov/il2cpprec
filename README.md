# il2cpprec

Experimental C++20 tool for recovering C#-style method bodies from Unity IL2CPP native binaries and metadata. It reads ELF, PE, and Mach-O images, supports ARM32, ARM64, x86, and x64 lifting, and records `exact`, `partial`, or `error` status with reasons for each method.

The generated C# project is experimental and is not guaranteed to compile. An `exact` status means that the tool did not record a partial-recovery reason; it is not proof that the recovered behavior matches the original managed method.

## Build

Requirements: CMake 3.28+, a C++20 compiler, and Capstone. The CLI is enabled by default.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

If CMake cannot find Capstone, set `CAPSTONE_ROOT` or both `CAPSTONE_INCLUDE_DIR` and `CAPSTONE_LIBRARY`.

## Usage

```sh
./build/il2cpprec_cli --inspect path/to/libil2cpp.so --metadata path/to/global-metadata.dat
./build/il2cpprec_cli --binary path/to/libil2cpp.so --metadata path/to/global-metadata.dat --output-dir build/recovered --report build/recovery.json
```

Run `./build/il2cpprec_cli --help` for architecture, filtering, version, and recovery options.

## Tests

`ctest` runs the core suite. Additional acceptance and differential runners are in `tests/acceptance` and `tests/differential`; some scenarios need .NET or user-supplied game binaries. Those binaries, local analysis, generated projects, and build outputs are excluded from this repository.

Known issue: the synthetic acceptance scenario currently fails while reading its generated metadata fixture. It is not part of `ctest`.

## Status

This is research software. Real-world recovery coverage varies by Unity version, architecture, and binary protection. Review the per-method JSON report before using generated code.
