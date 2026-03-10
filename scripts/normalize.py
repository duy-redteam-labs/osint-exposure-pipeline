from __future__ import annotations

import json
from pathlib import Path
from typing import Any


RAW_HEADERS_FILE = Path("data/raw/raw_headers.json")
RAW_ROUTES_FILE = Path("data/raw/raw_routes.json")
RAW_ARTIFACTS_FILE = Path("data/raw/raw_artifacts.json")
OUTPUT_FILE = Path("data/normalized/findings.json")


def load_json(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def make_finding(
    finding_id: str,
    target: str,
    category: str,
    title: str,
    source: str,
    evidence: str,
    confidence: str,
    severity: str,
    notes: str,
    timestamp: str,
) -> dict[str, Any]:
    return {
        "finding_id": finding_id,
        "target": target,
        "category": category,
        "title": title,
        "source": source,
        "evidence": evidence,
        "confidence": confidence,
        "severity": severity,
        "risk_score": 0,
        "notes": notes,
        "timestamp": timestamp,
    }


def normalize_headers(raw_headers: list[dict[str, Any]], start_index: int) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    counter = start_index

    informational_headers = {
        "content-type",
        "date",
        "connection",
        "keep-alive",
        "vary",
        "accept-ranges",
        "content-length",
        "x-frame-options",
        "x-content-type-options",
    }

    medium_value_headers = {
        "access-control-allow-origin",
        "cache-control",
        "etag",
        "last-modified",
        "feature-policy",
    }

    tech_headers = {
        "server",
        "x-powered-by",
        "x-generator",
        "x-aspnet-version",
        "x-runtime",
    }

    for item in raw_headers:
        target = item.get("target", "")
        source = item.get("source", "automated_http_collection")
        timestamp = item.get("timestamp", "")
        headers = item.get("observed_headers", {})

        for header_name, header_value in headers.items():
            if not header_value:
                continue

            header_name = str(header_name).strip().lower()
            header_value = str(header_value).strip()

            category = "header_disclosure"
            title = f"HTTP response header discloses {header_name}"
            confidence = "high"
            severity = "low"
            notes = "Observed directly in homepage response headers."

            if header_name in tech_headers:
                category = "tech_stack_footprint"
                title = f"Technology fingerprinting clue observed in {header_name}"
                severity = "medium"
                notes = "Header may help profile backend technology."

            elif header_name in medium_value_headers:
                category = "header_disclosure"
                severity = "medium"
                notes = "Header provides potentially useful reconnaissance value."

            elif header_name in informational_headers:
                category = "header_disclosure"
                severity = "low"
                notes = "Informational response header with limited direct exposure value."

            evidence = f"{header_name}: {header_value}"

            findings.append(
                make_finding(
                    finding_id=f"F-{counter:03d}",
                    target=target,
                    category=category,
                    title=title,
                    source=source,
                    evidence=evidence,
                    confidence=confidence,
                    severity=severity,
                    notes=notes,
                    timestamp=timestamp,
                )
            )
            counter += 1

    return findings


def normalize_routes(raw_routes: list[dict[str, Any]], start_index: int) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    counter = start_index
    seen_routes: set[str] = set()

    for item in raw_routes:
        route = str(item.get("route", "")).strip()
        if not route:
            continue

        if route in seen_routes:
            continue
        seen_routes.add(route)

        confidence = "medium"
        severity = "low"
        notes = item.get("notes", "Public route clue observed from application content.")

        route_lc = route.lower()
        if any(keyword in route_lc for keyword in ("rest", "api", "admin", "search", "assets", "public")):
            severity = "medium"
            confidence = "high"
            notes = "Route/path appears useful for profiling application structure."

        findings.append(
            make_finding(
                finding_id=f"F-{counter:03d}",
                target=item.get("target", ""),
                category="public_route_exposure",
                title="Public route or path clue observed",
                source=item.get("source", "automated_html_parsing"),
                evidence=f"Observed route/path: {route}",
                confidence=confidence,
                severity=severity,
                notes=notes,
                timestamp=item.get("timestamp", ""),
            )
        )
        counter += 1

    return findings


def normalize_artifacts(raw_artifacts: list[dict[str, Any]], start_index: int) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    counter = start_index

    for item in raw_artifacts:
        artifact_type = str(item.get("artifact_type", "")).strip()
        artifact_name = str(item.get("artifact_name", "")).strip()
        artifact_url = str(item.get("artifact_url", "")).strip()
        source = item.get("source", "automated_asset_extraction")
        timestamp = item.get("timestamp", "")

        if artifact_type == "metadata":
            # Giảm giá trị của metadata phổ thông
            low_value_meta = {"page_title", "viewport", "description", "theme-color"}
            if artifact_name.lower() in low_value_meta:
                severity = "low"
            else:
                severity = "low"

            category = "metadata_exposure"
            title = "Public metadata observed"
            confidence = "high"
            evidence = f"{artifact_name}: {item.get('evidence', '')}"
            notes = item.get("notes", "Metadata observed in public application content.")
        else:
            category = "client_side_artifact"
            title = "Public client-side artifact observed"
            confidence = "high"

            if artifact_type in {"javascript", "stylesheet"}:
                severity = "medium"
                notes = "Client-side artifact may assist application profiling."
            else:
                severity = "low"
                notes = item.get("notes", "Client-side artifact observed in public application content.")

            evidence = f"{artifact_type} artifact: {artifact_name} ({artifact_url})"

        findings.append(
            make_finding(
                finding_id=f"F-{counter:03d}",
                target=artifact_url or item.get("target", ""),
                category=category,
                title=title,
                source=source,
                evidence=evidence,
                confidence=confidence,
                severity=severity,
                notes=notes,
                timestamp=timestamp,
            )
        )
        counter += 1

    return findings


def main() -> None:
    raw_headers = load_json(RAW_HEADERS_FILE)
    raw_routes = load_json(RAW_ROUTES_FILE)
    raw_artifacts = load_json(RAW_ARTIFACTS_FILE)

    findings: list[dict[str, Any]] = []
    findings.extend(normalize_headers(raw_headers, start_index=1))
    findings.extend(normalize_routes(raw_routes, start_index=len(findings) + 1))
    findings.extend(normalize_artifacts(raw_artifacts, start_index=len(findings) + 1))

    save_json(OUTPUT_FILE, findings)

    print(f"[OK] Wrote {OUTPUT_FILE}")
    print(f"[INFO] Total findings normalized: {len(findings)}")


if __name__ == "__main__":
    main()