# OSINT Exposure Pipeline

## Overview
This project simulates a professional-style exposure assessment against an authorized lab target: an OWASP Juice Shop instance running in a controlled internal lab.

The goal is to practice structured reconnaissance, automated safe evidence collection, manual verification, finding normalization, risk scoring, and professional reporting without exploitation.

## Target
- OWASP Juice Shop
- Running inside a private lab environment
- Scope restricted to lab-owned assets only

## Objectives
- Perform safe reconnaissance and exposure observation
- Combine automated collection with manual verification
- Collect and preserve evidence with timestamps
- Normalize findings into a consistent schema
- Assign confidence, severity, and risk scores
- Generate a professional exposure report
- Produce a summary/dashboard for quick review

## Scope
Allowed:
- Passive observation of the lab target
- Light active observation such as normal HTTP requests, header inspection, and public route review
- Technology fingerprinting from public responses
- Automated collection of public responses and client-side artifacts within the lab scope
- Manual verification using browser developer tools

Not allowed:
- Exploitation
- Brute force
- Credential attacks
- Destructive testing
- Any activity outside the internal lab scope
- Any action that changes the system state unnecessarily

## Deliverables
- Reconnaissance and evidence collection scripts
- Normalized findings dataset
- Risk scoring logic
- Exposure report in Markdown
- Summary/dashboard JSON output
- Screenshots for documentation

## Repository Structure
- `data/raw/` - raw collected evidence
- `data/normalized/` - normalized findings, scored findings, and risk summary
- `docs/methodology.md` - methodology and assessment model
- `docs/finding_schema.md` - finding categories and schema
- `docs/reports/Exposure_Report.md` - final generated report
- `docs/screenshots/` - manual verification screenshots
- `scripts/collect.py` - raw evidence collection
- `scripts/normalize.py` - raw-to-finding transformation
- `scripts/score.py` - risk scoring and summary generation
- `scripts/build_report.py` - Markdown report generation
- `templates/` - report template files
- `tests/` - validation or scoring tests

## Workflow
1. Define scope and methodology
2. Run automated collection against the authorized lab target
3. Verify selected evidence manually in browser developer tools
4. Normalize findings
5. Score risk
6. Generate final report
7. Review and document outcomes

## How to Run

### 1. Install dependencies
```bash
pip install requests beautifulsoup4
```

### 2. Run collection
```bash
python scripts/collect.py http://YOUR-JUICE-SHOP-URL:3000
```

### 3. Normalize findings
```bash
python scripts/normalize.py
```

### 4. Score findings
```bash
python scripts/score.py
```

### 5. Build report
```bash
python scripts/build_report.py
```

## Example Output Files
- `data/raw/raw_headers.json`
- `data/raw/raw_routes.json`
- `data/raw/raw_artifacts.json`
- `data/normalized/findings.json`
- `data/normalized/scored_findings.json`
- `data/normalized/risk_summary.json`
- `docs/reports/Exposure_Report.md`

## Evidence Screenshots
Expected screenshot set:
- `docs/screenshots/headers/homepage_headers.png`
- `docs/screenshots/routes/homepage_route.png`
- `docs/screenshots/routes/public_page_1.png`
- `docs/screenshots/routes/public_page_2.png`
- `docs/screenshots/artifacts/public_assets_network.png`
- `docs/screenshots/artifacts/js_artifact_detail.png`

## Notes
This is a lab-only project for training and portfolio purposes. It does not target unauthorized real-world systems.
