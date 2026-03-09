# OSINT Exposure Pipeline

## Overview
This project simulates a professional-style exposure assessment against an authorized lab target: an OWASP Juice Shop instance running in a controlled internal lab.

The goal is to practice structured reconnaissance, evidence collection, finding normalization, risk scoring, and professional reporting without exploitation.

## Target
- OWASP Juice Shop
- Running inside a private lab environment
- Scope restricted to lab-owned assets only

## Objectives
- Perform safe reconnaissance and exposure observation
- Separate passive observation from light active observation
- Collect and preserve evidence with timestamps
- Normalize findings into a consistent schema
- Assign confidence, severity, and risk scores
- Generate a professional exposure report
- Produce a summary/dashboard for quick review

## Scope
Allowed:
- Passive observation of the lab target
- Light active observation such as HTTP requests, header inspection, and public route review
- Technology fingerprinting from public responses
- Documentation of publicly exposed metadata, routes, assets, and client-side artifacts

Not allowed:
- Exploitation
- Brute force
- Credential attacks
- Destructive testing
- Any activity outside the internal lab scope
- Any action that changes the system state unnecessarily

## Deliverables
- Reconnaissance/evidence collection scripts
- Normalized findings dataset
- Risk scoring logic
- Exposure report in Markdown
- Summary/dashboard table
- Screenshots for documentation

## Repository Structure
- `data/raw/` - raw collected evidence
- `data/normalized/` - normalized and scored findings
- `docs/` - methodology, reports, screenshots, and diagrams
- `scripts/` - collection, normalization, scoring, and reporting logic
- `templates/` - report templates
- `tests/` - tests for scoring or validation logic

## Workflow
1. Define scope and methodology
2. Collect safe evidence from the authorized lab target
3. Normalize findings
4. Score risk
5. Generate report
6. Review and document outcomes

## Notes
This is a lab-only project for training and portfolio purposes. It does not target unauthorized real-world systems.