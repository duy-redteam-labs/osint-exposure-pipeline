from __future__ import annotations

import json
from pathlib import Path
from typing import Any


INPUT_FILE = Path("data/normalized/findings.json")
SCORED_OUTPUT_FILE = Path("data/normalized/scored_findings.json")
SUMMARY_OUTPUT_FILE = Path("data/normalized/risk_summary.json")


BASE_SCORES = {
    "tech_stack_footprint": 45,
    "header_disclosure": 10,
    "public_route_exposure": 20,
    "client_side_artifact": 20,
    "metadata_exposure": 10,
}


def load_json(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def clamp_score(score: int) -> int:
    return max(0, min(score, 100))


def severity_from_score(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def calculate_score(finding: dict[str, Any]) -> int:
    category = str(finding.get("category", "")).lower()
    evidence = str(finding.get("evidence", "")).lower()
    title = str(finding.get("title", "")).lower()
    score = BASE_SCORES.get(category, 10)

    if category == "tech_stack_footprint":
        if "server" in evidence or "x-powered-by" in evidence or "x-generator" in evidence:
            score += 15
        if "version" in evidence:
            score += 10
        if "fingerprinting" in title:
            score += 5

    elif category == "header_disclosure":
        if "access-control-allow-origin" in evidence:
            score += 20
        elif "etag" in evidence or "last-modified" in evidence:
            score += 12
        elif "cache-control" in evidence or "feature-policy" in evidence:
            score += 10
        elif "server" in evidence or "x-powered-by" in evidence:
            score += 15
        elif any(
            h in evidence
            for h in (
                "content-type",
                "date",
                "connection",
                "keep-alive",
                "vary",
                "accept-ranges",
                "content-length",
                "x-frame-options",
                "x-content-type-options",
            )
        ):
            score += 0

    elif category == "public_route_exposure":
        if evidence.strip() == "observed route/path: /":
            score += 0
        else:
            if "/rest" in evidence or "rest" in evidence:
                score += 20
            if "/api" in evidence or "api" in evidence:
                score += 20
            if "admin" in evidence:
                score += 15
            if "search" in evidence:
                score += 10
            if "/assets" in evidence or "/public" in evidence:
                score += 5
            if "favicon" in evidence:
                score -= 5

    elif category == "client_side_artifact":
        if "javascript" in evidence:
            score += 8
        if ".js" in evidence:
            score += 8
        if "main.js" in evidence or "vendor.js" in evidence or "runtime.js" in evidence:
            score += 12
        elif "jquery" in evidence or "cookieconsent" in evidence:
            score += 6
        if "map" in evidence:
            score += 15
        if ".css" in evidence or "stylesheet" in evidence:
            score += 3
        if "favicon" in evidence:
            score -= 5

    elif category == "metadata_exposure":
        if "generator" in evidence:
            score += 10
        elif "title" in evidence:
            score += 2
        else:
            score += 0

    confidence = str(finding.get("confidence", "")).lower()
    if confidence == "high":
        score += 2
    elif confidence == "low":
        score -= 5

    return clamp_score(score)


def build_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    summary = {
        "total_findings": len(findings),
        "by_severity": {"high": 0, "medium": 0, "low": 0},
        "by_category": {},
        "top_findings": [],
    }

    for finding in findings:
        severity = finding.get("severity", "low")
        category = finding.get("category", "unknown")

        summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
        summary["by_category"][category] = summary["by_category"].get(category, 0) + 1

    sorted_findings = sorted(findings, key=lambda x: x.get("risk_score", 0), reverse=True)
    summary["top_findings"] = sorted_findings[:5]

    return summary


def main() -> None:
    findings = load_json(INPUT_FILE)

    for finding in findings:
        score = calculate_score(finding)
        finding["risk_score"] = score
        finding["severity"] = severity_from_score(score)

    save_json(SCORED_OUTPUT_FILE, findings)
    save_json(SUMMARY_OUTPUT_FILE, build_summary(findings))

    print(f"[OK] Wrote {SCORED_OUTPUT_FILE}")
    print(f"[OK] Wrote {SUMMARY_OUTPUT_FILE}")
    print(f"[INFO] Total findings scored: {len(findings)}")


if __name__ == "__main__":
    main()