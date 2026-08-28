# NetShield Phase 3 Engineering Handbook

## Welcome

This handbook explains the engineering journey behind NetShield Phase 3.

It is written for learners who want to understand the main decisions, improvements and lessons without reading every project file.

It complements the README. The README explains the project components and evidence in more detail, while this handbook focuses on how the project was built and what the work taught me.

The current implementation is complete through Stage 9.

## Engineering Goals

The goal of NetShield Phase 3 is to build a security-automation project inside a controlled Ubuntu VirtualBox sandbox.

The project is built one stage at a time. Each stage is tested, corrected, understood, documented and validated before the next stage begins.

The phase gradually added:

- A controlled security environment
- Security-event processing
- Identity and authentication detection
- Network and Wi-Fi detection
- Endpoint and wired-LAN monitoring
- SQL injection detection and secure query remediation
- Event correlation, risk scoring and IoC extraction
- Incident management and evidence handling
- Controlled containment automation

The aim is not to create a production security platform. The aim is to build a practical learning project that demonstrates security controls, detection logic, evidence handling, controlled response and engineering decisions.

## Engineering Principles

The following principles guided the work:

- Build one stage at a time.
- Keep testing inside the controlled sandbox.
- Test components before relying on their results.
- Use default deny and least privilege.
- Keep disruptive actions controlled.
- Preserve original evidence where possible.
- Reject invalid or inconsistent data.
- Prevent duplicate records and alert flooding.
- Revalidate earlier work after later changes.
- Fix genuine problems found during testing.
- Record meaningful engineering observations.
- Keep documentation aligned with the implementation.
- Use Git history to show real project progress.
- Write documentation as the engineer who built the project.
- Keep the writing simple, honest and technically accurate.

A result is not treated as complete only because a script runs. It must also match the evidence, tests and expected behaviour.

## What Was Built

### Stage 1 — Environment and Access Control

- Ubuntu VirtualBox sandbox
- Python environment
- Project configuration
- SQLite database
- Application and audit logging
- Application roles and permissions
- CYOD and IP controls
- Automation-action ACL
- Evidence hashing and protection

### Stage 2 — Security Data Pipeline

- Simulated security events
- JSONL event collection
- Event validation and normalisation
- UTC timestamp handling
- Accepted and rejected event storage
- Duplicate-event protection
- Import-batch tracking
- Raw-event preservation

### Stage 3 — Identity and Authentication Detection

- Failed-login and brute-force detection
- Successful login after failures
- MFA anomaly detection
- New-device and unusual-location detection
- Impossible-travel detection
- Suspicious role-change detection
- VPN exceptions
- False-positive investigation
- Identity-alert storage

### Stage 4 — Network, CYOD and Wi-Fi Detection

- Network and Wi-Fi event generation
- Suspicious IP and repeated-connection detection
- Port-scanning detection
- Unknown-device and MAC-reuse detection
- Wi-Fi zone checks
- WPA3 and WPA2 policy checks
- Rogue access-point detection
- MAC-based alert correlation

### Stage 5 — Endpoint and Wired-LAN Detection

- Endpoint CPU monitoring
- Approved and unauthorised stress-test handling
- Repeated high-CPU detection
- Unknown-process detection
- Restricted wired-access detection
- Simulated Server Room checks
- Endpoint-alert storage
- Repeated wired-observation grouping

### Stage 6 — SQL Injection Detection

- Separate local SQL injection lab
- Separate SQLite test database
- Vulnerable login query
- Parameterised login query
- Suspicious-input detection
- Authentication-bypass testing
- Database-error monitoring
- Source-IP tracking
- Remediation retesting

### Stage 7 — Event Correlation, Risk Scoring and IoCs

- Controlled cross-source events
- Event correlation by identity and time
- Multi-source incident grouping
- Configurable risk scoring
- Low, Medium, High and Critical severity
- Approved-device and VPN exceptions
- IoC extraction
- Behaviour classification
- Separation of IoCs from behaviours
- Isolated low-value alert reduction

### Stage 8 — Incident Management and Evidence

- Unique incident records
- Detection name, severity and risk score
- Controlled incident status lifecycle
- Investigation notes
- Analyst decisions
- False-positive classification
- Preserved Stage 7 evidence
- SHA-256 evidence hashes
- Incident timelines
- IoC tables
- JSON incident records
- Human-readable incident reports
- Complete audit trail

### Stage 9 — Controlled Containment

- Simulated IP blocklist action
- Unknown CYOD device quarantine
- Temporary account restriction
- Simulated session revocation
- Suspicious-process isolation
- Non-compliant Wi-Fi rejection
- Evidence preservation before each action
- Approval checks for disruptive actions
- Success and failure results
- Containment audit trail
- Controlled containment report

## Major Engineering Decisions

The following decisions kept the project safe and understandable:

- Ubuntu VirtualBox keeps testing separate from the Windows host and public systems.
- SQLite suits the single-VM learning environment.
- JSON configuration keeps rules separate from program logic.
- Default deny prevents unknown roles, actions, sources and values from being trusted.
- CYOD provides a controlled device inventory for testing.
- The MAC address is used as the primary device identity, with other fields providing context.
- JSONL allows one malformed record to be rejected without stopping the complete file.
- UTC timestamps provide one timeline for events from different sources.
- Invalid input is preserved with a reason instead of being silently deleted.
- Separate source files preserve the existing validation rules.
- Alert and incident keys prevent repeated processing from creating duplicates.
- Approved activity is represented in test data so it is not incorrectly reported.
- The SQL injection lab uses a separate database so it cannot affect the main NetShield data.
- Parameterised SQL treats input as data instead of SQL instructions.
- Correlation requires identity evidence and a time relationship.
- IoCs are kept separate from behaviours because they support different investigation decisions.
- Incident records connect detections, evidence, decisions and timelines.
- SHA-256 provides an integrity check for preserved evidence.
- Evidence is preserved before containment actions.
- Automatic blocklisting is separated from disruptive actions that require approval.
- Containment remains simulated so the project does not change real devices, accounts or networks.

## Improvements Made

The project improved as problems were found:

- Added validation for timestamps, IP addresses, MAC addresses and CPU values.
- Added rejected-event and import-batch tracking.
- Added identity, network, Wi-Fi, endpoint and wired-LAN detection.
- Added false-positive investigation.
- Added MAC-based correlation.
- Added approved CPU stress-test handling.
- Corrected source filenames after records were rejected.
- Corrected SQL placeholder handling.
- Corrected stage initialisation so earlier metadata was preserved.
- Added endpoint-alert storage to the tracked schema.
- Corrected MAC-reuse logic so a location change alone was not enough.
- Corrected the Stage 6 bypass summary after it undercounted the evidence.
- Corrected Stage 6 logging so tests could use an isolated log path.
- Archived cumulative Stage 6 logs before the clean run.
- Corrected Stage 7 IoC extraction so usernames remained context.
- Corrected Stage 7 scoring so isolated low-value activity was reduced.
- Added Stage 8 incident records and evidence references.
- Added SHA-256 verification for preserved Stage 7 evidence.
- Added incident timelines, analyst decisions and audit entries.
- Added Stage 9 simulated containment actions.
- Added approval handling for disruptive containment actions.
- Added success and failure results for every containment action.
- Re-ran tests and validators after each relevant correction.

## Lessons Learned

The project taught me that:

- A safe foundation should come before detection or response work.
- Normalised data is easier to search and compare.
- Source validation should happen before correlation.
- A detection is evidence for investigation, not automatic proof of compromise.
- A MAC address, username or source IP is not complete proof of identity.
- Approved activity must be represented in test data.
- High CPU usage is not automatically malicious.
- SQL injection can occur when user input is joined directly into a query.
- Parameterised queries treat input as data instead of executable SQL.
- Database errors and failed injection attempts can still provide useful evidence.
- Several related indicators can provide stronger context than one isolated alert.
- IoCs and behaviours should not be mixed together.
- Exceptions reduce risk but do not erase evidence.
- Clean-run evidence is important because cumulative logs can produce misleading totals.
- Summary output must be checked against the underlying records.
- Evidence should be preserved before incident handling or containment.
- A containment action can fail safely when approval is missing.
- Failed actions must remain visible in the audit trail.
- Real test failures show where components do not connect correctly.
- Documentation should reflect the actual implementation, problems, fixes and lessons.

## Future Expansion

Stages 1–9 provide a foundation for later security-operations work.

The next expansion can build on the existing events, alerts, incidents, risk scores, preserved evidence and containment records by adding:

- Eradication records
- Malware and process-removal decisions
- Root-cause investigation
- Recovery actions
- Service restoration checks
- Post-incident review
- Incident closure criteria
- Final clean-state project validation and sign-off
