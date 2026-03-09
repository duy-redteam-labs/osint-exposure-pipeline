# Methodology

## Assessment Type
Professional-style exposure assessment focused on reconnaissance, observation, evidence collection, normalization, scoring, and reporting.

## Target
OWASP Juice Shop running inside a private internal lab environment.

## Assessment Goals
- Identify publicly observable exposure points
- Record evidence in a structured manner
- Classify findings by category
- Estimate confidence and severity
- Assign a risk score
- Summarize exposure in a report suitable for portfolio demonstration

## Scope Definition

### In Scope
- The OWASP Juice Shop instance deployed in the internal lab
- Publicly reachable pages within the lab target
- HTTP response headers
- Client-side artifacts such as JavaScript references and static assets
- Public routes and visible application metadata
- Technology clues observable through normal browsing and safe requests

### Out of Scope
- Any system outside the internal lab
- Exploitation attempts
- Brute force or credential attacks
- Privilege escalation
- State-changing actions unless strictly required for harmless observation
- Denial-of-service or abusive traffic generation

## Reconnaissance Model

### Passive Observation
Examples:
- Reviewing visible content in the browser
- Observing application structure
- Recording asset names, route clues, and page metadata
- Documenting public-facing technology indicators

### Light Active Observation
Examples:
- Sending normal HTTP requests
- Inspecting HTTP response headers
- Fetching public pages and static resources
- Reviewing client-side artifacts returned by the application

## Evidence Handling
Each finding should preserve:
- timestamp
- source
- target
- category
- evidence text
- notes
- confidence
- severity
- risk score

Evidence should be stored first in raw form, then transformed into normalized findings.

## Finding Categories
Suggested categories:
- `tech_stack_footprint`
- `header_disclosure`
- `public_route_exposure`
- `client_side_artifact`
- `metadata_exposure`

## Risk Evaluation
Each finding will be reviewed using:
- **Confidence**: how reliable the evidence is
- **Severity**: how important the exposure appears
- **Risk Score**: numeric estimate for prioritization

Example interpretation:
- Low: informational exposure with limited impact
- Medium: useful reconnaissance value or unnecessary disclosure
- High: highly valuable exposure that could materially assist follow-on attacks

## Reporting Outputs
The final report should include:
- Executive summary
- Methodology
- Findings table
- Risk matrix
- Recommendations
- Limitations

## Limitations
This assessment is intentionally restricted to safe, authorized, non-exploit reconnaissance activity in a controlled lab.