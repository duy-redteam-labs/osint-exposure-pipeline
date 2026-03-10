# Methodology

## Assessment Type
Professional-style exposure assessment focused on reconnaissance, automated safe evidence collection, analyst verification, normalization, scoring, and reporting.

## Target
OWASP Juice Shop running inside a private internal lab environment.

## Assessment Goals
- Identify publicly observable exposure points
- Collect evidence in a structured and repeatable manner
- Combine automated collection with manual verification
- Classify findings by category
- Estimate confidence and severity
- Assign a risk score
- Summarize exposure in a report suitable for portfolio demonstration

## Scope Definition

### In Scope
- The OWASP Juice Shop instance deployed in the internal lab
- Publicly reachable pages within the lab target
- HTTP response headers
- HTML metadata
- Client-side artifacts such as JavaScript references, CSS files, and static assets
- Public routes and visible application metadata
- Technology clues observable through normal browsing and safe requests
- Automated collection of public responses and client-side artifacts within the lab scope

### Out of Scope
- Any system outside the internal lab
- Exploitation attempts
- Brute force or credential attacks
- Privilege escalation
- State-changing actions unless strictly required for harmless observation
- Denial-of-service or abusive traffic generation
- Aggressive enumeration, fuzzing, or intrusive scanning outside the intended project scope

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

### Automated Safe Collection
Examples:
- Sending normal requests to publicly reachable pages
- Collecting response headers programmatically
- Parsing HTML for titles, meta tags, scripts, and stylesheets
- Extracting publicly referenced assets and basic route clues
- Writing raw evidence to structured JSON files for later processing

### Manual Validation
Examples:
- Verifying automatically collected evidence in the browser
- Confirming important findings using developer tools
- Capturing screenshots for documentation and report support
- Adding analyst notes where interpretation is needed

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

Evidence should be collected first in raw form, validated as needed, and then transformed into normalized findings.

## Data Collection Workflow
1. Run automated collection against the authorized lab target
2. Review collected headers, metadata, assets, and route clues
3. Validate important observations manually in the browser
4. Normalize findings into a standard schema
5. Apply confidence, severity, and risk scoring
6. Generate the final exposure report

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
This assessment is intentionally restricted to safe, authorized, non-exploit reconnaissance activity in a controlled lab. It is designed to document publicly observable exposure rather than perform vulnerability exploitation or intrusive testing.