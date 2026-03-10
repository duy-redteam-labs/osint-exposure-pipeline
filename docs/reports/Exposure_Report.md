# Exposure Report

## Executive Summary

This report summarizes a professional-style exposure assessment conducted against **OWASP Juice Shop** running in a controlled internal lab environment.

A total of **27 findings** were identified through automated safe evidence collection and analyst verification. The findings were categorized, normalized, and risk-scored to support structured reporting.

Severity distribution:
- High: **0**
- Medium: **8**
- Low: **19**

The assessment focused on publicly observable exposure points such as HTTP headers, route clues, client-side artifacts, and metadata. No exploitation, brute force, or intrusive testing was performed.

## Scope

**Target:** OWASP Juice Shop

**Target URL:** `http://192.168.168.30:3000`

**In Scope:**
- Publicly reachable pages within the lab target
- HTTP response headers
- HTML metadata
- Client-side artifacts such as JavaScript, CSS, and static assets
- Public route and path clues
- Publicly observable technology indicators

**Out of Scope:**
- Exploitation
- Brute force
- Credential attacks
- Privilege escalation
- Intrusive scanning or aggressive enumeration
- Any activity outside the internal lab environment

## Methodology

The assessment followed a professional-style exposure assessment workflow:

1. Safe automated collection of public responses from the authorized lab target
2. Extraction of headers, route clues, metadata, and client-side artifacts
3. Manual verification of selected findings using browser developer tools
4. Normalization of raw observations into a structured finding schema
5. Risk scoring based on category, evidence content, and confidence
6. Final reporting and evidence documentation

This assessment was intentionally restricted to non-exploit reconnaissance and exposure observation.

## Findings Summary

| Category | Count |
|---|---:|
| `client_side_artifact` | 9 |
| `header_disclosure` | 13 |
| `metadata_exposure` | 3 |
| `public_route_exposure` | 2 |

## Risk Matrix

| Severity | Count | Meaning |
|---|---:|---|
| High | 0 | High reconnaissance value or materially useful exposure |
| Medium | 8 | Useful profiling or structural exposure |
| Low | 19 | Informational exposure with limited direct impact |

## Top Findings

### F-018 - Public client-side artifact observed

- Category: `client_side_artifact`
- Severity: **medium**
- Risk Score: **50**
- Evidence: javascript artifact: runtime.js (http://192.168.168.30:3000/runtime.js)
- Notes: Client-side artifact may assist application profiling.

### F-020 - Public client-side artifact observed

- Category: `client_side_artifact`
- Severity: **medium**
- Risk Score: **50**
- Evidence: javascript artifact: vendor.js (http://192.168.168.30:3000/vendor.js)
- Notes: Client-side artifact may assist application profiling.

### F-021 - Public client-side artifact observed

- Category: `client_side_artifact`
- Severity: **medium**
- Risk Score: **50**
- Evidence: javascript artifact: main.js (http://192.168.168.30:3000/main.js)
- Notes: Client-side artifact may assist application profiling.

### F-016 - Public client-side artifact observed

- Category: `client_side_artifact`
- Severity: **medium**
- Risk Score: **44**
- Evidence: javascript artifact: cookieconsent.min.js (http://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js)
- Notes: Client-side artifact may assist application profiling.

### F-017 - Public client-side artifact observed

- Category: `client_side_artifact`
- Severity: **medium**
- Risk Score: **44**
- Evidence: javascript artifact: jquery.min.js (http://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js)
- Notes: Client-side artifact may assist application profiling.

## Findings Table

| ID | Category | Severity | Score | Title | Evidence |
|---|---|---|---:|---|---|
| F-001 | `header_disclosure` | low | 12 | HTTP response header discloses content-type | content-type: text/html; charset=UTF-8 |
| F-002 | `header_disclosure` | low | 12 | HTTP response header discloses accept-ranges | accept-ranges: bytes |
| F-003 | `header_disclosure` | medium | 32 | HTTP response header discloses access-control-allow-origin | access-control-allow-origin: * |
| F-004 | `header_disclosure` | low | 22 | HTTP response header discloses cache-control | cache-control: public, max-age=0 |
| F-005 | `header_disclosure` | low | 24 | HTTP response header discloses last-modified | last-modified: Tue, 10 Mar 2026 10:22:10 GMT |
| F-006 | `header_disclosure` | low | 24 | HTTP response header discloses etag | etag: W/"1252f-19cd744b7d6" |
| F-007 | `header_disclosure` | low | 12 | HTTP response header discloses vary | vary: Accept-Encoding |
| F-008 | `header_disclosure` | low | 12 | HTTP response header discloses date | date: Tue, 10 Mar 2026 10:25:03 GMT |
| F-009 | `header_disclosure` | low | 12 | HTTP response header discloses connection | connection: keep-alive |
| F-010 | `header_disclosure` | low | 12 | HTTP response header discloses keep-alive | keep-alive: timeout=5 |
| F-011 | `header_disclosure` | low | 12 | HTTP response header discloses x-frame-options | x-frame-options: SAMEORIGIN |
| F-012 | `header_disclosure` | low | 12 | HTTP response header discloses x-content-type-options | x-content-type-options: nosniff |
| F-013 | `header_disclosure` | low | 22 | HTTP response header discloses feature-policy | feature-policy: payment 'self' |
| F-014 | `public_route_exposure` | low | 20 | Public route or path clue observed | Observed route/path: / |
| F-015 | `public_route_exposure` | low | 22 | Public route or path clue observed | Observed route/path: /public/favicon_js.ico |
| F-016 | `client_side_artifact` | medium | 44 | Public client-side artifact observed | javascript artifact: cookieconsent.min.js (http://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js) |
| F-017 | `client_side_artifact` | medium | 44 | Public client-side artifact observed | javascript artifact: jquery.min.js (http://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js) |
| F-018 | `client_side_artifact` | medium | 50 | Public client-side artifact observed | javascript artifact: runtime.js (http://192.168.168.30:3000/runtime.js) |
| F-019 | `client_side_artifact` | medium | 38 | Public client-side artifact observed | javascript artifact: polyfills.js (http://192.168.168.30:3000/polyfills.js) |
| F-020 | `client_side_artifact` | medium | 50 | Public client-side artifact observed | javascript artifact: vendor.js (http://192.168.168.30:3000/vendor.js) |
| F-021 | `client_side_artifact` | medium | 50 | Public client-side artifact observed | javascript artifact: main.js (http://192.168.168.30:3000/main.js) |
| F-022 | `client_side_artifact` | low | 17 | Public client-side artifact observed | linked_resource artifact: favicon_js.ico (http://192.168.168.30:3000/assets/public/favicon_js.ico) |
| F-023 | `client_side_artifact` | medium | 31 | Public client-side artifact observed | stylesheet artifact: cookieconsent.min.css (http://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.css) |
| F-024 | `client_side_artifact` | low | 25 | Public client-side artifact observed | stylesheet artifact: styles.css (http://192.168.168.30:3000/styles.css) |
| F-025 | `metadata_exposure` | low | 14 | Public metadata observed | page_title: Observed page title: OWASP Juice Shop |
| F-026 | `metadata_exposure` | low | 12 | Public metadata observed | description: Observed meta tag content: Probably the most modern and sophisticated insecure web application |
| F-027 | `metadata_exposure` | low | 12 | Public metadata observed | viewport: Observed meta tag content: width=device-width, initial-scale=1 |

## Recommendations

- Minimize unnecessary response header disclosure where possible.
- Review publicly exposed route and path clues to reduce reconnaissance value.
- Assess whether client-side artifacts reveal avoidable implementation detail.
- Review metadata exposure for unnecessary profiling clues.
- Continue periodic internal lab assessments using the same collection and scoring workflow.

## Limitations

- This assessment was limited to safe and authorized lab activity.
- No exploitation or intrusive testing was performed.
- Findings represent publicly observable exposure rather than confirmed vulnerabilities.
- Some route clues and client-side artifacts may require analyst interpretation to determine their practical significance.

## Evidence Screenshots

### Header Evidence
- `docs/screenshots/headers/homepage_headers.png`

### Route / Public Page Evidence
- `docs/screenshots/routes/homepage_route.png`
- `docs/screenshots/routes/public_page_1.png`
- `docs/screenshots/routes/public_page_2.png`

### Client-Side Artifact Evidence
- `docs/screenshots/artifacts/public_assets_network.png`
- `docs/screenshots/artifacts/js_artifact_detail.png`
