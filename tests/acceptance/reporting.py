from __future__ import annotations

from typing import Any


QUALITY_KEYS = ("exact", "partial", "errors")
VERIFICATION_LEVELS = ("metadata-supported", "provisional", "native-verified", "unverified")


def empty_recovery() -> dict[str, int]:
    return {key: 0 for key in QUALITY_KEYS}


def recovery_from_cli(report: dict[str, Any]) -> dict[str, int]:
    result: dict[str, int] = {}
    for key in QUALITY_KEYS:
        value = report.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"CLI report has invalid {key} count")
        result[key] = value
    return result


def total_recovery(cases: list[dict[str, Any]]) -> dict[str, int]:
    result = empty_recovery()
    for case in cases:
        recovery = case.get("recovery", {})
        for key in QUALITY_KEYS:
            value = recovery.get(key, 0)
            if isinstance(value, int) and not isinstance(value, bool):
                result[key] += value
    return result


def make_case(
    case_id: str,
    suite: str,
    status: str,
    verification: str,
    reason: str,
    recovery: dict[str, int] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    if verification not in VERIFICATION_LEVELS:
        raise ValueError(f"unknown verification level: {verification}")
    case = {
        "id": case_id,
        "suite": suite,
        "status": status,
        "verification": verification,
        "reason": reason,
        "recovery": recovery or empty_recovery(),
    }
    case.update(extra)
    return case


def build_report(cases: list[dict[str, Any]], cli: str, diff: dict[str, Any] | None = None) -> dict[str, Any]:
    failed = sum(case["status"] == "FAIL" for case in cases)
    report = {
        "schemaVersion": 1,
        "runner": "il2cpprec-version-acceptance",
        "cli": cli,
        "status": "FAIL" if failed else "PASS",
        "totals": {
            "passed": sum(case["status"] == "PASS" for case in cases),
            "failed": failed,
            "skipped": sum(case["status"] == "SKIP" for case in cases),
            "metadataSupported": sum(case["verification"] == "metadata-supported" and case["status"] == "PASS" for case in cases),
            "provisional": sum(case["verification"] == "provisional" and case["status"] == "PASS" for case in cases),
            "nativeVerified": sum(case["verification"] == "native-verified" and case["status"] == "PASS" for case in cases),
        },
        "recovery": total_recovery(cases),
        "cases": cases,
    }
    if diff is not None:
        report["diff"] = diff
    return report


def _baseline_recovery(report: dict[str, Any]) -> dict[str, int]:
    recovery = report.get("recovery")
    if not isinstance(recovery, dict):
        raise ValueError("baseline does not contain aggregate recovery counts")
    result: dict[str, int] = {}
    for key in QUALITY_KEYS:
        value = recovery.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"baseline has invalid {key} count")
        result[key] = value
    return result


def diff_reports(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    if before.get("schemaVersion") != 1 or before.get("runner") != "il2cpprec-version-acceptance":
        raise ValueError("baseline is not an il2cpprec version acceptance report")
    before_recovery = _baseline_recovery(before)
    after_recovery = _baseline_recovery(after)
    delta = {key: after_recovery[key] - before_recovery[key] for key in QUALITY_KEYS}

    before_cases = before.get("cases")
    if not isinstance(before_cases, list):
        raise ValueError("baseline does not contain a case list")
    before_by_id = {case["id"]: case for case in before_cases if isinstance(case, dict) and "id" in case}
    after_by_id = {case["id"]: case for case in after["cases"]}
    changes: list[dict[str, Any]] = []
    for case_id in sorted(before_by_id.keys() | after_by_id.keys()):
        old = before_by_id.get(case_id)
        new = after_by_id.get(case_id)
        old_recovery = old.get("recovery", empty_recovery()) if old else empty_recovery()
        new_recovery = new.get("recovery", empty_recovery()) if new else empty_recovery()
        case_delta = {
            key: new_recovery.get(key, 0) - old_recovery.get(key, 0)
            for key in QUALITY_KEYS
        }
        if (
            old is not None and new is not None
            and old.get("status") == new.get("status")
            and old.get("verification") == new.get("verification")
            and not any(case_delta.values())
        ):
            continue
        changes.append({
            "id": case_id,
            "beforeStatus": old.get("status") if old else "ABSENT",
            "afterStatus": new.get("status") if new else "ABSENT",
            "beforeVerification": old.get("verification") if old else "ABSENT",
            "afterVerification": new.get("verification") if new else "ABSENT",
            "delta": case_delta,
        })
    return {
        "before": before_recovery,
        "after": after_recovery,
        "delta": delta,
        "cases": changes,
    }


def signed(value: int) -> str:
    return f"{value:+d}"
