from __future__ import annotations

import sys
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from corpus_gate import compare_baseline, gate_status, parse_compiler_output, summarize_cli  # noqa: E402


class CorpusGateTests(unittest.TestCase):
    def report(self) -> dict:
        return {
            "total": 2, "exact": 1, "partial": 1, "errors": 0,
            "methods": [
                {"image": "Assembly-CSharp.dll", "status": "exact", "reasons": []},
                {"image": "Other.dll", "status": "partial", "reasons": ["unknown"]},
            ],
            "options": {"includedImages": ["Assembly-CSharp.dll"]},
            "projectEmission": {
                "scope": "native-exact-inputs", "supported": 0, "partial": 0,
                "unsupported": 1, "declarationOnly": 0, "omitted": 0,
                "methods": [{"status": "unsupported", "reason":
                             "native register 'x0' has no managed ABI value"}],
            },
            "sourceProfile": {"id": "il2cpp-24-base", "variant": "24.0",
                              "confidence": "compatible", "selectionMode": "auto"},
        }

    def test_native_exact_stays_separate_from_emitted_csharp(self) -> None:
        summary = summarize_cli(self.report(), "Assembly-CSharp.dll")
        self.assertEqual(summary["targetImage"]["exact"], 1)
        self.assertEqual(summary["csharp"]["supported"], 0)
        self.assertEqual(summary["csharp"]["unsupported"], 1)
        self.assertEqual(summary["csharp"]["reasons"][0]["count"], 1)
        self.assertEqual(summary["csharp"]["attribution"], "legacy-filter")
        self.assertEqual(summary["csharpAllImages"]["methods"], 1)

    def test_full_declarations_excludes_external_image_from_target_counts(self) -> None:
        report = self.report()
        report["total"] = 2
        report["exact"] = 2
        report["partial"] = 0
        report["methods"][1]["status"] = "exact"
        report["options"]["fullDeclarations"] = True
        report["projectEmission"].update({"supported": 1, "unsupported": 0, "omitted": 1})
        report["projectEmission"]["methods"] = [
            {"image": "Assembly-CSharp.dll", "address": "0x1000", "status": "supported", "reason": ""},
            {"image": "Other.dll", "address": "0x1000", "status": "omitted", "reason": "body filter"},
        ]
        summary = summarize_cli(report, "Assembly-CSharp.dll")
        self.assertEqual(summary["csharp"]["attribution"], "explicit-image")
        self.assertEqual(summary["csharp"]["supported"], 1)
        self.assertEqual(summary["csharp"]["omitted"], 0)
        self.assertEqual(summary["csharpAllImages"]["omitted"], 1)
        self.assertEqual(summary["csharpAllImages"]["images"][1]["name"], "Other.dll")
        self.assertEqual(summary["csharpAllImages"]["images"][1]["omitted"], 1)

        report["projectEmission"]["methods"][1].pop("image")
        with self.assertRaisesRegex(ValueError, "nonempty image for every method"):
            summarize_cli(report, "Assembly-CSharp.dll")
        report["projectEmission"]["methods"][1]["image"] = "  "
        with self.assertRaisesRegex(ValueError, "nonempty image for every method"):
            summarize_cli(report, "Assembly-CSharp.dll")

        # Shared native addresses cannot establish which assembly owns a body.
        for method in report["projectEmission"]["methods"]:
            method.pop("image")
        with self.assertRaisesRegex(ValueError, "lacks per-method image"):
            summarize_cli(report, "Assembly-CSharp.dll")

    def test_emission_summary_order_is_deterministic(self) -> None:
        report = self.report()
        first = summarize_cli(report, "Assembly-CSharp.dll")
        report["methods"].reverse()
        report["projectEmission"]["methods"].reverse()
        second = summarize_cli(report, "Assembly-CSharp.dll")
        self.assertEqual(first, second)

    def test_emission_count_mismatch_is_rejected(self) -> None:
        report = self.report()
        report["projectEmission"]["supported"] = 1
        with self.assertRaisesRegex(ValueError, "disagrees"):
            summarize_cli(report, "Assembly-CSharp.dll")

    def test_compiler_deduplicates_build_summary(self) -> None:
        line = "/tmp/generated/Foo.cs(3,4): error CS0234: Missing type [/tmp/generated/Out.csproj]"
        output = f"{line}\n{line}\n    1 Error(s)\n"
        result = parse_compiler_output(output, 1, Path("/tmp/generated"))
        self.assertEqual(result["errors"], 1)
        self.assertEqual(result["codes"], [{"code": "CS0234", "count": 1}])
        self.assertEqual(result["sample"][0]["source"], "<PROJECT>/Foo.cs(3,4)")

    def test_baseline_tracks_supported_compiler_and_project_digest(self) -> None:
        base = {"schemaVersion": 1, "runner": "il2cpprec-corpus-gate",
                "input": {"binarySha256": "a", "metadataSha256": "b"},
                "cliArguments": ["--full-metadata"], "cliOptions": {"fullMetadata": True},
                "targetImage": {"name": "Assembly-CSharp.dll", "exact": 10},
                "csharp": {"supported": 4, "partial": 1, "unsupported": 5, "omitted": 0},
                "compiler": {"errors": 2}, "projectSha256": "old"}
        now = {**base, "targetImage": {"name": "Assembly-CSharp.dll", "exact": 11},
               "csharp": {"supported": 5, "partial": 1, "unsupported": 4, "omitted": 1},
               "compiler": {"errors": 1}, "projectSha256": "new"}
        delta = compare_baseline(base, now)
        self.assertEqual(delta["csharpDelta"]["supported"], 1)
        self.assertEqual(delta["nativeExactDelta"], 1)
        self.assertEqual(delta["compilerErrorDelta"], -1)
        self.assertTrue(delta["projectChanged"])

        now["cliArguments"] = []
        with self.assertRaisesRegex(Exception, "CLI arguments"):
            compare_baseline(base, now)

    def test_observe_never_masks_oracle_or_native_failure(self) -> None:
        compile_issue = "generated C# project does not compile"
        self.assertEqual(gate_status([compile_issue], True), "OBSERVED")
        self.assertEqual(gate_status([compile_issue, "private oracle failed"], True), "FAIL")
        self.assertEqual(gate_status(["target image has native recovery errors"], True), "FAIL")


if __name__ == "__main__":
    unittest.main()
