# Finding Schema

## Purpose
This document defines the finding categories, the standard data structure for each finding, and the collection checklist used in the OWASP Juice Shop exposure assessment project.

The goal is to ensure that all collected evidence can be normalized, scored, and reported consistently.

---

## Finding Categories

The project uses the following finding categories:

### 1. `tech_stack_footprint`
Technology clues observable from public responses or client-side artifacts.

Examples:
- server/framework hints
- library names
- JavaScript bundle naming patterns
- public indicators of application stack

### 2. `header_disclosure`
Information disclosed through HTTP response headers.

Examples:
- `Server`
- `X-Powered-By`
- other response headers that reveal unnecessary implementation details

### 3. `public_route_exposure`
Publicly observable application routes, paths, and endpoint clues.

Examples:
- visible pages
- client-side route references
- public endpoint names referenced in static resources

### 4. `client_side_artifact`
Artifacts exposed to the client during normal application use.

Examples:
- JavaScript files
- CSS files
- asset names
- route clues visible in public code
- source map references if present

### 5. `metadata_exposure`
Metadata or supporting clues that help profile the target.

Examples:
- HTML title
- meta tags
- comments in public source
- branding clues
- version clues if publicly visible

---

## Standard Finding Structure

Each finding should follow a consistent structure so that it can be processed automatically by the pipeline.

### Required Fields
- `finding_id`
- `target`
- `category`
- `title`
- `source`
- `evidence`
- `confidence`
- `severity`
- `risk_score`
- `notes`
- `timestamp`

### Field Definitions

#### `finding_id`
Unique identifier for the finding.

Example:
- `F-001`
- `F-002`

#### `target`
The specific target, page, path, or resource related to the finding.

Examples:
- `http://juice-shop.lab`
- `/`
- `/assets/public/images`
- `/rest/products/search`

#### `category`
One of the approved finding categories:
- `tech_stack_footprint`
- `header_disclosure`
- `public_route_exposure`
- `client_side_artifact`
- `metadata_exposure`

#### `title`
A short professional-style description of the finding.

Examples:
- `Server header discloses backend technology`
- `Public JavaScript bundle reveals route structure`
- `Visible metadata exposes application branding`

#### `source`
The method or source from which the finding was derived.

Examples:
- `manual_browser_observation`
- `http_header_inspection`
- `public_js_review`
- `html_source_review`
- `automated_http_collection`
- `automated_html_parsing`
- `automated_asset_extraction`
- `manual_validation`

#### `evidence`
The supporting observation, quoted or summarized briefly and clearly.

Example:
- `Response header includes: Server: nginx/1.18.0`

#### `confidence`
How reliable the finding is.

Allowed values:
- `high`
- `medium`
- `low`

Interpretation:
- `high`: directly observed and clearly supported
- `medium`: reasonably inferred from visible evidence
- `low`: weak signal or incomplete indication

#### `severity`
The assessed importance of the finding.

Allowed values:
- `low`
- `medium`
- `high`

Interpretation:
- `low`: informational exposure with limited impact
- `medium`: useful for profiling or expanding target understanding
- `high`: materially valuable exposure that could support follow-on attacks

#### `risk_score`
A numeric value used for prioritization.

Examples:
- `20`
- `40`
- `65`

#### `notes`
Additional context explaining why the finding matters.

Example:
- `Useful for attacker reconnaissance and technology profiling`

#### `timestamp`
The collection time in ISO 8601 format.

Example:
- `2026-03-10T01:00:00Z`

---

## Example Finding JSON

```json
{
  "finding_id": "F-001",
  "target": "http://juice-shop-lab",
  "category": "header_disclosure",
  "title": "Server header discloses backend technology",
  "source": "manual_browser_observation",
  "evidence": "Response header includes: Server: nginx/1.18.0",
  "confidence": "high",
  "severity": "medium",
  "risk_score": 50,
  "notes": "Useful for attacker reconnaissance and technology profiling",
  "timestamp": "2026-03-10T01:00:00Z"
}
```

---

## Confidence Guidance

### High Confidence
Use when the evidence is directly visible and unambiguous.

Examples:
- response header explicitly shows a value
- a file name is clearly visible in browser developer tools
- a public route is directly observable

### Medium Confidence
Use when the finding is supported but involves some interpretation.

Examples:
- framework clues inferred from naming patterns
- route structure inferred from public JavaScript references

### Low Confidence
Use when the signal is weak or only partially supported.

Examples:
- incomplete artifact reference
- uncertain technology inference

---

## Severity Guidance

### Low Severity
Informational findings with limited direct impact.

Examples:
- generic metadata
- minor branding clues
- low-value artifact naming

### Medium Severity
Findings that increase profiling capability or reveal useful structural information.

Examples:
- backend/server disclosure
- route exposure
- clear stack fingerprinting clues

### High Severity
Findings that significantly improve attacker understanding or enable more effective follow-on activity.

Examples:
- highly specific technology disclosure
- unusually revealing route or endpoint exposure
- strongly actionable implementation details exposed publicly

Note:
Most findings in this project are expected to be `low` or `medium`, which is normal for a non-exploit exposure assessment.

---

## Collection Checklist

The collection process for this project will focus on the following observation areas:

### 1. Browser Observation
Review:
- homepage
- visible navigation
- public pages
- visible application structure
- branding and interface clues

### 2. Header Inspection
Review:
- HTTP response headers
- technology disclosure headers
- content-type and related response metadata
- any unnecessary implementation detail leakage

### 3. Client-Side Artifact Review
Review:
- public JavaScript files
- CSS files
- asset names
- route clues in client-side code
- referenced public resources

### 4. Metadata Review
Review:
- page title
- meta tags
- comments in public HTML or JS
- public branding or version clues

---

## Data Handling Model

### Raw Data
Initial observations should first be preserved as raw evidence.

Suggested raw evidence groupings:
- `raw_headers.json`
- `raw_routes.json`
- `raw_artifacts.json`

### Normalized Data
Raw observations will then be transformed into a standardized finding structure for scoring and reporting.

### Scored Data
Normalized findings will later receive:
- confidence
- severity
- risk score

---

## Summary

This schema is intended to make the project:
- structured
- consistent
- automatable
- easy to report
- closer to a professional assessment workflow
