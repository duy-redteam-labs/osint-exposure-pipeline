import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.score import calculate_score, severity_from_score


def test_access_control_allow_origin_scores_higher_than_content_type():
    finding_cors = {
        "category": "header_disclosure",
        "evidence": "access-control-allow-origin: *",
        "title": "HTTP response header discloses access-control-allow-origin",
        "confidence": "high",
    }

    finding_content_type = {
        "category": "header_disclosure",
        "evidence": "content-type: text/html; charset=UTF-8",
        "title": "HTTP response header discloses content-type",
        "confidence": "high",
    }

    assert calculate_score(finding_cors) > calculate_score(finding_content_type)


def test_runtime_js_scores_higher_than_basic_metadata():
    finding_js = {
        "category": "client_side_artifact",
        "evidence": "javascript artifact: runtime.js (http://example/runtime.js)",
        "title": "Public client-side artifact observed",
        "confidence": "high",
    }

    finding_meta = {
        "category": "metadata_exposure",
        "evidence": "page_title: Observed page title: OWASP Juice Shop",
        "title": "Public metadata observed",
        "confidence": "high",
    }

    assert calculate_score(finding_js) > calculate_score(finding_meta)


def test_severity_mapping():
    assert severity_from_score(10) == "low"
    assert severity_from_score(35) == "medium"
    assert severity_from_score(65) == "high"