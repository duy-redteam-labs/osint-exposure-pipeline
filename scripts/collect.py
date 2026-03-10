from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


RAW_DIR = Path("data/raw")
RAW_HEADERS_FILE = RAW_DIR / "raw_headers.json"
RAW_ROUTES_FILE = RAW_DIR / "raw_routes.json"
RAW_ARTIFACTS_FILE = RAW_DIR / "raw_artifacts.json"

DEFAULT_TIMEOUT = 10

# Các path/tag rác hay bị regex bắt nhầm từ HTML
NOISE_ROUTE_VALUES = {
    "/html",
    "/head",
    "/body",
    "/title",
    "/style",
    "/script",
    "/noscript",
    "/meta",
    "/link",
    "/div",
    "/span",
    "/app-root",
    "/css",
    "/js",
    "/20px",
    "/utf-8",
    "/icon",
    "/x-icon",
}


def iso_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_header_subset(headers: requests.structures.CaseInsensitiveDict) -> dict[str, str]:
    wanted = [
        "content-type",
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-runtime",
        "x-generator",
        "accept-ranges",
        "access-control-allow-origin",
        "cache-control",
        "last-modified",
        "etag",
        "content-length",
        "vary",
        "date",
        "connection",
        "keep-alive",
        "x-frame-options",
        "x-content-type-options",
        "feature-policy",
    ]
    normalized: dict[str, str] = {}
    for key in wanted:
        normalized[key] = headers.get(key, "")
    return normalized


def extract_title(soup: BeautifulSoup) -> str:
    if soup.title and soup.title.string:
        return soup.title.string.strip()
    return ""


def extract_meta_tags(soup: BeautifulSoup) -> list[dict[str, str]]:
    meta_items: list[dict[str, str]] = []
    for tag in soup.find_all("meta"):
        name = tag.get("name", "") or tag.get("property", "") or tag.get("charset", "")
        content = tag.get("content", "")

        name = str(name).strip()
        content = str(content).strip()

        # Bỏ meta charset đơn giản kiểu utf-8 vì ít giá trị exposure
        if name.lower() in {"utf-8", "charset"} and not content:
            continue

        if name or content:
            meta_items.append({"name": name, "content": content})

    return meta_items


def extract_assets(base_url: str, soup: BeautifulSoup) -> list[dict[str, str]]:
    assets: list[dict[str, str]] = []

    for script in soup.find_all("script", src=True):
        src = script.get("src", "").strip()
        if src:
            assets.append(
                {
                    "target": base_url,
                    "artifact_type": "javascript",
                    "artifact_name": src.split("/")[-1] or src,
                    "artifact_url": urljoin(base_url, src),
                    "source": "automated_asset_extraction",
                    "evidence": "Public JavaScript asset observed in HTML source",
                    "notes": "Useful for identifying client-side structure and technology clues",
                    "timestamp": iso_timestamp(),
                }
            )

    for link in soup.find_all("link", href=True):
        href = link.get("href", "").strip()
        rel = " ".join(link.get("rel", []))
        if href:
            artifact_type = "stylesheet" if "stylesheet" in rel.lower() else "linked_resource"
            assets.append(
                {
                    "target": base_url,
                    "artifact_type": artifact_type,
                    "artifact_name": href.split("/")[-1] or href,
                    "artifact_url": urljoin(base_url, href),
                    "source": "automated_asset_extraction",
                    "evidence": "Public linked asset observed in HTML source",
                    "notes": "Useful for documenting client-side artifacts and referenced resources",
                    "timestamp": iso_timestamp(),
                }
            )

    for img in soup.find_all("img", src=True):
        src = img.get("src", "").strip()
        if src:
            assets.append(
                {
                    "target": base_url,
                    "artifact_type": "image",
                    "artifact_name": src.split("/")[-1] or src,
                    "artifact_url": urljoin(base_url, src),
                    "source": "automated_asset_extraction",
                    "evidence": "Public image asset observed in HTML source",
                    "notes": "Useful for documenting publicly referenced static assets",
                    "timestamp": iso_timestamp(),
                }
            )

    return deduplicate_dict_list(assets)


def is_meaningful_route(route: str) -> bool:
    if not route:
        return False

    route = route.strip()

    if route in NOISE_ROUTE_VALUES:
        return False

    if route.startswith("//"):
        return False

    if len(route) < 2:
        return False

    # asset path thì vẫn có thể hữu ích
    if route.startswith("/assets/") or route.startswith("/public/"):
        return True

    # route có vẻ hữu ích cho recon
    meaningful_keywords = ("rest", "api", "admin", "search", "assets", "public")
    if any(keyword in route.lower() for keyword in meaningful_keywords):
        return True

    # Cho phép homepage
    if route == "/":
        return True

    # Loại bớt các path quá generic chỉ 1 segment ngắn
    parts = [p for p in route.split("/") if p]
    if len(parts) == 1 and parts[0].lower() in {
        "html",
        "head",
        "body",
        "title",
        "style",
        "script",
        "noscript",
        "meta",
        "link",
        "div",
        "span",
        "app-root",
        "css",
        "js",
        "icon",
        "x-icon",
    }:
        return False

    # Chỉ giữ route có cấu trúc rõ hơn
    return len(parts) >= 2


def extract_visible_routes(base_url: str, soup: BeautifulSoup, html_text: str) -> list[dict[str, str]]:
    routes: list[dict[str, str]] = []

    routes.append(
        {
            "target": base_url,
            "route": "/",
            "observation_type": "visible_page",
            "source": "automated_html_parsing",
            "evidence": "Homepage is publicly reachable",
            "notes": "Landing page of the application",
            "timestamp": iso_timestamp(),
        }
    )

    for anchor in soup.find_all("a", href=True):
        href = anchor.get("href", "").strip()
        if not href:
            continue
        if href.startswith("#") or href.startswith("javascript:"):
            continue

        parsed = urlparse(urljoin(base_url, href))
        route = parsed.path or "/"

        if not is_meaningful_route(route):
            continue

        routes.append(
            {
                "target": base_url,
                "route": route,
                "observation_type": "anchor_reference",
                "source": "automated_html_parsing",
                "evidence": "Route observed through anchor reference in public HTML",
                "notes": "Publicly referenced route in application markup",
                "timestamp": iso_timestamp(),
            }
        )

    route_patterns = re.findall(r'\/[A-Za-z0-9_\-\/\.]+', html_text)
    for pattern in route_patterns:
        if not is_meaningful_route(pattern):
            continue

        routes.append(
            {
                "target": base_url,
                "route": pattern,
                "observation_type": "path_clue",
                "source": "automated_html_parsing",
                "evidence": "Route-like string observed in public HTML",
                "notes": "Useful as a basic route clue for analyst review",
                "timestamp": iso_timestamp(),
            }
        )

    return deduplicate_routes(routes)


def extract_metadata_artifacts(base_url: str, soup: BeautifulSoup) -> list[dict[str, str]]:
    artifacts: list[dict[str, str]] = []

    page_title = extract_title(soup)
    if page_title:
        artifacts.append(
            {
                "target": base_url,
                "artifact_type": "metadata",
                "artifact_name": "page_title",
                "artifact_url": base_url,
                "source": "automated_html_parsing",
                "evidence": f"Observed page title: {page_title}",
                "notes": "Supports metadata exposure assessment",
                "timestamp": iso_timestamp(),
            }
        )

    for meta in extract_meta_tags(soup):
        meta_name = meta["name"] or "meta"
        meta_content = meta["content"]

        # Loại bớt metadata quá yếu
        if meta_name.lower() in {"utf-8", "charset"} and not meta_content:
            continue

        artifacts.append(
            {
                "target": base_url,
                "artifact_type": "metadata",
                "artifact_name": meta_name,
                "artifact_url": base_url,
                "source": "automated_html_parsing",
                "evidence": f"Observed meta tag content: {meta_content}",
                "notes": "Supports metadata exposure assessment",
                "timestamp": iso_timestamp(),
            }
        )

    return deduplicate_dict_list(artifacts)


def deduplicate_dict_list(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    unique_items: list[dict[str, Any]] = []

    for item in items:
        key = json.dumps(item, sort_keys=True)
        if key not in seen:
            seen.add(key)
            unique_items.append(item)

    return unique_items


def deduplicate_routes(routes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    unique_routes: list[dict[str, Any]] = []

    for route in routes:
        key = (route.get("route", ""), route.get("observation_type", ""))
        if key not in seen:
            seen.add(key)
            unique_routes.append(route)

    return unique_routes


def write_json(path: Path, data: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def collect(base_url: str) -> None:
    try:
        response = requests.get(base_url, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f"[ERROR] Failed to fetch target: {exc}")
        sys.exit(1)

    soup = BeautifulSoup(response.text, "html.parser")
    timestamp = iso_timestamp()

    raw_headers = [
        {
            "target": base_url,
            "path": urlparse(base_url).path or "/",
            "method": "GET",
            "status_code": response.status_code,
            "source": "automated_http_collection",
            "observed_headers": normalize_header_subset(response.headers),
            "notes": "Homepage response header observation collected automatically",
            "timestamp": timestamp,
        }
    ]

    raw_routes = extract_visible_routes(base_url, soup, response.text)
    raw_artifacts = extract_assets(base_url, soup) + extract_metadata_artifacts(base_url, soup)
    raw_artifacts = deduplicate_dict_list(raw_artifacts)

    write_json(RAW_HEADERS_FILE, raw_headers)
    write_json(RAW_ROUTES_FILE, raw_routes)
    write_json(RAW_ARTIFACTS_FILE, raw_artifacts)

    print(f"[OK] Wrote {RAW_HEADERS_FILE}")
    print(f"[OK] Wrote {RAW_ROUTES_FILE}")
    print(f"[OK] Wrote {RAW_ARTIFACTS_FILE}")
    print(f"[INFO] Headers collected: {len(raw_headers)}")
    print(f"[INFO] Route clues collected: {len(raw_routes)}")
    print(f"[INFO] Artifacts collected: {len(raw_artifacts)}")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python scripts/collect.py <target_url>")
        sys.exit(1)

    target_url = sys.argv[1].strip()
    collect(target_url)


if __name__ == "__main__":
    main()