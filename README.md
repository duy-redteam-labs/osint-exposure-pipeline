# OSINT Exposure Pipeline (Lab/Demo Scope)

## Overview
Automated OSINT pipeline for collecting public-scope signals, normalizing data, and producing an exposure report with simple risk scoring.

## Scope (Controlled & Legal)
Only for yourself, demo domains, or CTF-approved targets. Public sources only.

## Pipeline
Sources (public) → Collect → Normalize → Score → Report

## Tech Stack
- Python (requests/bs4), or Go (optional)
- Output: JSON/CSV
- Report: Markdown → PDF

## How to Run
1. Configure target in config/ (or environment variables)
2. Run collector scripts in scripts/
3. Generate report in docs/reports/

## Deliverables
- Report template: docs/reports/
- Collection + normalization scripts: scripts/
- Summary dashboard/table: docs/reports/

## Status
- [ ] Data schema
- [ ] Collectors
- [ ] Scoring
- [ ] Report template
