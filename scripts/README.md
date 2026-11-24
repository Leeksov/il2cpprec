# Corpus regression gates

These gates use caller-supplied IL2CPP binaries and metadata; no commercial game corpus is included. Build `il2cpprec_cli` first. The CLI path defaults to `build/il2cpprec_cli` from the repository root, or pass `--cli`.

## Determinism

```sh
python3 scripts/regression_gate.py determinism \
  --binary /path/to/GameAssembly.dll \
  --metadata /path/to/global-metadata.dat \
  --report /tmp/determinism.json
```

The gate runs two separate CLI processes with one worker, hashes each method's JSON record by image, index, address, and name, and hashes each generated C# project file. Differences are reported by method identity and relative file path. This checks repeatability, not correctness. It does not compare incidental log or timing text.

## Managed-reference differential

```sh
python3 scripts/regression_gate.py differential \
  --binary /path/to/GameAssembly.dll \
  --metadata /path/to/global-metadata.dat \
  --managed /path/to/original/Managed \
  --min-agreement 0.50 \
  --report /tmp/differential.json
```

Requires the .NET 8 SDK. The gate builds the generated C# project, reads both original and recovered DLLs without loading them, and compares sets of named method calls, field references, and string literals for uniquely matched recovered target methods. Match keys are declaring type, method name, and parameter count. Ambiguous overloads and unmatched methods are reported separately. Compiler failure, malformed IL, or no matched target methods fails the gate. A match is a useful structural signal, not proof of semantic equivalence: IL2CPP optimization can legitimately inline or alter operations. Choose a threshold from a measured baseline; without `--min-agreement`, the result is `OBSERVED` and exit 0 means the measurement completed.

Both commands return exit 0 for a completed passing or observation-only run, 1 for a failed comparison or processing error, and 2 for a missing input, tool, or invalid invocation. Temporary output is removed after each run. No user-supplied path is deleted.
