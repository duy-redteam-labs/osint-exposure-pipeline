from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SCORED_FINDINGS_FILE = Path("data/normalized/scored_findings.json")
RISK_SUMMARY_FILE = Path("data/normalized/risk_summary.json")
OUTPUT_REPORT_FILE = Path("docs/reports/Exposure_Report.md")


TARGET_NAME = "OWASP Juice Shop"
TARGET_URL = "http://192.168.168.30:3000"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def escape_md(text: str) -> str:
    return (
        str(text)
        .replace("|", "\\|")
        .replace("\n", " ")
        .replace("\r", " ")
    )


def build_executive_summary(summary: dict[str, Any]) -> list[str]:
    total = summary.get("total_findings", 0)
    sev = summary.get("by_severity", {})
    high = sev.get("high", 0)
    medium = sev.get("medium", 0)
    low = sev.get("low", 0)

    lines = [
        "## Executive Summary",
        "",
        f"This report summarizes a professional-style exposure assessment conducted against **{TARGET_NAME}** running in a controlled internal lab environment.",
        "",
        f"A total of **{total} findings** were identified through automated safe evidence collection and analyst verification. The findings were categorized, normalized, and risk-scored to support structured reporting.",
        "",
        f"Severity distribution:",
        f"- High: **{high}**",
        f"- Medium: **{medium}**",
        f"- Low: **{low}**",
        "",
        "The assessment focused on publicly observable exposure points such as HTTP headers, route clues, client-side artifacts, and metadata. No exploitation, brute force, or intrusive testing was performed.",
        "",
    ]
    return lines


def build_scope_section() -> list[str]:
    return [
        "## Scope",
        "",
        f"**Target:** {TARGET_NAME}",
        "",
        f"**Target URL:** `{TARGET_URL}`",
        "",
        "**In Scope:**",
        "- Publicly reachable pages within the lab target",
        "- HTTP response headers",
        "- HTML metadata",
        "- Client-side artifacts such as JavaScript, CSS, and static assets",
        "- Public route and path clues",
        "- Publicly observable technology indicators",
        "",
        "**Out of Scope:**",
        "- Exploitation",
        "- Brute force",
        "- Credential attacks",
        "- Privilege escalation",
        "- Intrusive scanning or aggressive enumeration",
        "- Any activity outside the internal lab environment",
        "",
    ]


def build_methodology_section() -> list[str]:
    return [
        "## Methodology",
        "",
        "The assessment followed a professional-style exposure assessment workflow:",
        "",
        "1. Safe automated collection of public responses from the authorized lab target",
        "2. Extraction of headers, route clues, metadata, and client-side artifacts",
        "3. Manual verification of selected findings using browser developer tools",
        "4. Normalization of raw observations into a structured finding schema",
        "5. Risk scoring based on category, evidence content, and confidence",
        "6. Final reporting and evidence documentation",
        "",
        "This assessment was intentionally restricted to non-exploit reconnaissance and exposure observation.",
        "",
    ]


def build_findings_summary(summary: dict[str, Any]) -> list[str]:
    by_category = summary.get("by_category", {})
    lines = [
        "## Findings Summary",
        "",
        "| Category | Count |",
        "|---|---:|",
    ]

    for category, count in sorted(by_category.items()):
        lines.append(f"| `{escape_md(category)}` | {count} |")

    lines.append("")
    return lines


def build_findings_table(findings: list[dict[str, Any]]) -> list[str]:
    lines = [
        "## Findings Table",
        "",
        "| ID | Category | Severity | Score | Title | Evidence |",
        "|---|---|---|---:|---|---|",
    ]

    for finding in findings:
        lines.append(
            "| "
            f"{escape_md(finding.get('finding_id', ''))} | "
            f"`{escape_md(finding.get('category', ''))}` | "
            f"{escape_md(finding.get('severity', ''))} | "
            f"{finding.get('risk_score', 0)} | "
            f"{escape_md(finding.get('title', ''))} | "
            f"{escape_md(finding.get('evidence', ''))} |"
        )

    lines.append("")
    return lines


def build_risk_matrix(summary: dict[str, Any]) -> list[str]:
    sev = summary.get("by_severity", {})
    lines = [
        "## Risk Matrix",
        "",
        "| Severity | Count | Meaning |",
        "|---|---:|---|",
        f"| High | {sev.get('high', 0)} | High reconnaissance value or materially useful exposure |",
        f"| Medium | {sev.get('medium', 0)} | Useful profiling or structural exposure |",
        f"| Low | {sev.get('low', 0)} | Informational exposure with limited direct impact |",
        "",
    ]
    return lines


def build_top_findings(summary: dict[str, Any]) -> list[str]:
    top_findings = summary.get("top_findings", [])
    lines = [
        "## Top Findings",
        "",
    ]

    if not top_findings:
        lines.append("No top findings were available.")
        lines.append("")
        return lines

    for finding in top_findings:
        lines.extend(
            [
                f"### {finding.get('finding_id', '')} - {finding.get('title', '')}",
                "",
                f"- Category: `{finding.get('category', '')}`",
                f"- Severity: **{finding.get('severity', '')}**",
                f"- Risk Score: **{finding.get('risk_score', 0)}**",
                f"- Evidence: {finding.get('evidence', '')}",
                f"- Notes: {finding.get('notes', '')}",
                "",
            ]
        )

    return lines


def build_recommendations() -> list[str]:
    return [
        "## Recommendations",
        "",
        "- Minimize unnecessary response header disclosure where possible.",
        "- Review publicly exposed route and path clues to reduce reconnaissance value.",
        "- Assess whether client-side artifacts reveal avoidable implementation detail.",
        "- Review metadata exposure for unnecessary profiling clues.",
        "- Continue periodic internal lab assessments using the same collection and scoring workflow.",
        "",
    ]


def build_limitations() -> list[str]:
    return [
        "## Limitations",
        "",
        "- This assessment was limited to safe and authorized lab activity.",
        "- No exploitation or intrusive testing was performed.",
        "- Findings represent publicly observable exposure rather than confirmed vulnerabilities.",
        "- Some route clues and client-side artifacts may require analyst interpretation to determine their practical significance.",
        "",
    ]


def build_evidence_section() -> list[str]:
    return [
        "## Evidence Screenshots",
        "",
        "### Header Evidence",
        "- `docs/screenshots/headers/homepage_headers.png`",
        "",
        "### Route / Public Page Evidence",
        "- `docs/screenshots/routes/homepage_route.png`",
        "- `docs/screenshots/routes/public_page_1.png`",
        "- `docs/screenshots/routes/public_page_2.png`",
        "",
        "### Client-Side Artifact Evidence",
        "- `docs/screenshots/artifacts/public_assets_network.png`",
        "- `docs/screenshots/artifacts/js_artifact_detail.png`",
        "",
    ]


def main() -> None:
    findings = load_json(SCORED_FINDINGS_FILE)
    summary = load_json(RISK_SUMMARY_FILE)

    lines: list[str] = []
    lines.append("# Exposure Report")
    lines.append("")
    lines.extend(build_executive_summary(summary))
    lines.extend(build_scope_section())
    lines.extend(build_methodology_section())
    lines.extend(build_findings_summary(summary))
    lines.extend(build_risk_matrix(summary))
    lines.extend(build_top_findings(summary))
    lines.extend(build_findings_table(findings))
    lines.extend(build_recommendations())
    lines.extend(build_limitations())
    lines.extend(build_evidence_section())

    OUTPUT_REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_REPORT_FILE.write_text("\n".join(lines), encoding="utf-8")

    print(f"[OK] Wrote {OUTPUT_REPORT_FILE}")
    print(f"[INFO] Report lines: {len(lines)}")


if __name__ == "__main__":
    main()