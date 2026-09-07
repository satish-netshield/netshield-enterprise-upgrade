# Notes from Testing

## Stage 1 observations

- Ubuntu 26.04 LTS provided Python 3.14.4, Git 2.53.0 and SQLite 3.46.1.
- The VirtualBox NAT interface was registered as the first approved CYOD test asset.
- Eleven access-control tests passed.
- Stage 1 validation passed all 12 checks.
- SHA-256 evidence verification passed after the preserved file was made read-only.

## Stage 2 observations

- Five simulated JSONL sources produced 19 records.
- Fifteen records were accepted and four malformed records were rejected.
- Rejected records retained their filename, line number, original input and failure reason.
- Timestamps with a `+12:00` offset were converted to UTC.
- Invalid IP addresses, missing event IDs, invalid JSON and CPU values above 100 were rejected.
- Duplicate-event protection was confirmed with an isolated temporary database.
- Stage 2 validation passed `14/14`.

## Stage 3 observations

- Sixteen simulated authentication events were imported successfully.
- The identity detector created 11 alerts.
- Repeated failures, possible brute force, successful login after failures, MFA anomalies, new devices, unusual locations, impossible travel and suspicious role changes were detected.
- A second detector run created zero new alerts and counted 11 existing alerts.
- Two approved VPN events were recorded as exceptions.
- The Stage 2 validator initially counted Stage 3 authentication events as original Stage 2 data.
- The validator was corrected to check only the original Stage 2 source files.
- The replacement laptop generated a new-device alert because it was authorised but not yet registered in the CYOD inventory.
- The alert was investigated and classified as a false positive with an audit record.
- Eleven Stage 3 detector tests passed.
- Stage 3 validation passed `12/12`.

## Stage 4 observations

- The first generator created 17 mixed network and Wi-Fi records.
- Six Wi-Fi records were rejected because the source type did not match the network-named file.
- The generator was changed to create separate network and Wi-Fi files.
- Six additional correlation events were generated.
- The database contained 23 accepted Stage 4 events after the corrected import.
- The first detection runner supplied four source files to a query with only two SQL placeholders.
- The runner was corrected to create the required placeholders dynamically.
- MAC-based correlation grouped related activity while keeping different devices separate.
- Twelve correlated alerts were produced.
- MAC reuse, port scanning, repeated connections, WPA3 violation, WPA2 downgrade and rogue access-point detections were confirmed.
- The rogue access point was classified as Critical.
- A repeated detector run created zero new alerts and counted 12 existing alerts.
- Stage 4 setup initially reset completed Stage 3 metadata.
- The initializer was corrected to preserve the earlier completion status.
- Five Stage 4 correlation tests passed.
- Stage 4 validation passed `12/12`.

## Stage 5 observations

- Stage 5 generated 10 endpoint events and 4 wired-LAN events.
- The first wired file used a filename that did not match its `network` source type.
- The importer rejected the wired records because of the source-type mismatch.
- The generator was corrected to create `network_stage5_events.jsonl`.
- The endpoint-alert table was initially created only by the Stage 5 initializer.
- The tracked schema was updated so clean initialisation also creates `endpoint_alerts`.
- The first MAC-reuse rule treated a location change alone as possible spoofing.
- The rule was corrected to require conflicting hostname or username evidence with overlapping event times.
- Simulated role mappings were added because the application role table contains only the project administrator.
- Analyst access to the simulated Server Room created a High restricted-wired-access alert.
- Approved responder access did not create an alert.
- Approved CPU stress testing did not create an alert.
- Unapproved CPU stress tests, unexpected CPU activity and unknown endpoint processes were detected.
- Three high-CPU events from the same MAC were grouped into one alert.
- Two restricted wired observations from the same MAC, zone and time window were grouped.
- Different MAC addresses remained separate investigations.
- Re-importing the same events rejected all 14 records as duplicates.
- A repeated detector run created zero new alerts and counted 10 existing alerts.
- Eight Stage 5 detector tests passed.
- Stage 5 validation passed `12/12`.

## Stage 6 observations

- Stage 6 was created as a separate local SQL injection lab.
- The lab used a separate SQLite database and one test account.
- No external target, public system or real account was used.
- The vulnerable login function demonstrated unsafe string-concatenated SQL.
- The input `' OR 1=1 --` bypassed authentication in the vulnerable function.
- The same input failed against the parameterised function.
- The users table remained present after testing.
- The first request summary reported two vulnerable bypasses.
- The generated evidence showed four vulnerable requests had authenticated.
- The summary logic was corrected to count actual vulnerable authentication results.
- One test did not verify the generated log because the application used a fixed log path.
- The application and test were corrected to accept an isolated log path.
- Three abnormal requests from `192.0.2.44` were identified as repeated activity.
- One malformed vulnerable request produced a database error.
- The previous application log contained 36 cumulative events.
- The previous log was archived before the clean validation run.
- The clean run produced seven requests and seven application events.
- Four vulnerable authentication bypasses were identified.
- One parameterised retest blocked the bypass.
- Seven Stage 6 unit tests passed.
- Stage 6 validation passed `15/15`.

## Stage 7 observations

- Stage 7 used seven controlled correlation events.
- The events represented authentication, network, endpoint and application activity.
- Four events sharing identity fields and a time window were combined into one incident.
- The main incident contained four source types and received a Critical score of 30.
- An approved-device and known-VPN group received a Low score of 1.
- One isolated Medium network event was initially scored too strongly.
- Isolated low-value activity was reduced to Low with a score of 3.
- The first IoC extraction included the username.
- The extraction logic was corrected so usernames remain incident context.
- The corrected main incident contained four IoCs: IP address, MAC address, hostname and process name.
- Repeated failed logins and repeated connection attempts remained behaviours rather than IoCs.
- Approved-device and known-VPN exceptions reduced risk without removing the original evidence.
- Three incidents were created from seven events.
- Five Stage 7 correlation tests passed.
- Stage 7 validation passed `15/15`.
- Automatic containment remained disabled.

## Stage 8 observations

- Stage 8 used the existing Stage 7 correlation report as its input.
- Three Stage 7 incidents were converted into three incident records.
- Each incident received a unique incident ID.
- The incidents preserved the detection name, severity, risk score and source event IDs.
- All three incidents started in `New` status.
- The Stage 7 report was copied into the Stage 8 evidence directory.
- The preserved evidence received the SHA-256 hash `10e94c774ace7897059c2a3713e1cb74697f3c1eb037efa98fcdd394e1a4efef`.
- The same evidence hash was recorded in the incident records and reports.
- Human-readable reports included investigation notes, analyst decisions, false-positive fields, IoCs, evidence and timelines.
- Nine audit entries were created: three incident records, three evidence-preservation actions and three analyst-decision records.
- Valid status transitions were accepted.
- Invalid status transitions were rejected.
- Ten Stage 8 unit tests passed.
- Stage 8 validation passed.
- Automatic containment was not performed in Stage 8.
- Eradication and recovery were not performed in Stage 8.

## Stage 9 observations

- Stage 9 used the Stage 8 incident summary and preserved evidence.
- Evidence was preserved before every simulated containment action.
- The same SHA-256 hash was recorded with every action result.
- Six containment actions were attempted.
- Five actions succeeded and one action failed.
- Adding the suspicious IP to the simulated blocklist succeeded without approval because it is defined as an automatic action.
- Device quarantine succeeded after approval.
- Account restriction succeeded after approval.
- Simulated session revocation succeeded after approval.
- Suspicious-process isolation succeeded after approval.
- Non-compliant Wi-Fi rejection failed safely because approval was not granted.
- Unknown containment actions were denied.
- Every action recorded its target, approval state, evidence hash, timestamp and result.
- Six containment audit entries were created.
- Eleven Stage 9 unit tests passed.
- Stage 9 validation passed.
- No external targets or real accounts were used.
- Automatic real-world containment remained disabled.
- Eradication and recovery remained separate from Stage 9.

## Stage 10 observations

- Stage 10 used the Stage 9 containment report and preserved pre-eradication evidence.
- Ten simulated eradication and recovery actions were attempted.
- All ten actions succeeded.
- The actions covered simulated credential reset, privilege removal, device registration, WPA3 correction, rogue access-point removal, suspicious-process removal, parameterised SQL remediation, service restoration and increased monitoring.
- Evidence was preserved before every eradication or recovery action.
- Four original-threat retests were performed after the actions.
- All four retests were blocked.
- The incident lifecycle progressed from `Contained` to `Eradicated`, `Recovered` and `Closed`.
- The Stage 10 audit trail contained 14 entries: ten action records and four retest records.
- Seven Stage 10 unit tests passed.
- Stage 10 validation passed.
- Real accounts, external targets and real-world eradication actions were not used.

## Stage 11 observations

- The first Stage 11 validator printed blank labels for several validator results.
- The validator output was corrected so each Stage 1–10 validator has an explicit label.
- The regression check was corrected to handle unittest output written to standard error.
- Clean-state validation confirmed that the required project files and documentation were present.
- Python syntax compilation passed for the project source, scripts, tests and lab files.
- The complete Stage 1–10 regression run passed 92 tests.
- Stage 1 through Stage 10 validators passed.
- Stage 7 correlation evidence, incidents and IoCs remained available.
- Stage 8 incident records and evidence hashes remained valid.
- Stage 9 containment actions and approval rejection remained recorded.
- Stage 10 eradication actions, blocked retests and the Closed lifecycle remained recorded.
- Clean-state, normal-activity, confirmed-threat, false-positive, malformed-input, duplicate-event, ACL, evidence-integrity, containment, eradication, recovery, IoC and audit-trail checks passed.
- Previous components remained operational after the later-stage work.
- Documentation files were checked for presence.
- Stage 11 validation passed.

## Combined validation observations

- The final combined Stage 1–10 regression run passed 92 tests.
- Stage 1 validation passed `12/12`.
- Stage 2 validation passed `14/14`.
- Stage 3 validation passed `12/12`.
- Stage 4 validation passed `12/12`.
- Stage 5 validation passed `12/12`.
- Stage 6 validation passed `15/15`.
- Stage 7 validation passed `15/15`.
- Stage 8 validation passed.
- Stage 9 validation passed.
- Stage 10 validation passed.
- Stage 11 full project validation passed.
- `git diff --check` passed.
- Runtime data, logs and generated reports remained excluded from Git.

## Engineering lessons

- A result must be checked against the underlying evidence, not only a summary line.
- Source validation must happen before correlation.
- A detection is evidence for investigation, not automatic proof of compromise.
- Approved activity must be represented in test data so it is not incorrectly reported.
- A MAC address, username or source IP should not be treated as complete proof of identity.
- Several related indicators can provide stronger context than one isolated alert.
- IoCs and behaviours have different meanings and should remain separate.
- Clean-run data is important because cumulative logs can produce misleading totals.
- Evidence must be preserved before incident handling or containment.
- SHA-256 confirms whether preserved evidence has changed.
- Disruptive containment actions require approval.
- Failed containment actions must remain in the audit trail.
- Incident status changes should follow a controlled lifecycle.
- Eradication should be followed by retesting to confirm that the original threat no longer works.
- Recovery actions should be recorded rather than assumed to be complete.
- Full regression testing exposes integration problems that isolated tests may not show.
- Validator output must identify each check clearly so a passing result can be trusted.
- Documentation should be checked against the actual implementation and final validation evidence.
- Later project phases can replace simulated response actions with approved integrations while preserving the same evidence and approval controls.
- Each genuine failure should be corrected and retested.

## Phase 3A V2 Stage 1 observations

- The original Phase 3 baseline passed 85 unit tests and all existing validators before the upgrade began.
- Direct validator execution failed because the project package path was unavailable. Module execution with `python -m` worked correctly.
- SQL injection lab runtime files appeared as untracked because the existing ignore rules covered only the main output directories. The nested lab paths were added to `.gitignore`.
- `CYOD-002` was registered in the enterprise context but missing from the authoritative CYOD inventory. The inventory was corrected and a consistency test was added.
- Sensitive-field masking protects configured nested values while leaving safe fields unchanged.
- Repeated V2 initialisation kept one role assignment per simulated user.
- The completed Stage 1 extension passed 91 unit tests, V2 validation and the original full-project validation.
- During repository separation, restoring the tracked `settings.json` file changed its local permission from `640` to `664`. Git does not preserve detailed non-executable permission modes, so `640` was reapplied and the Automation project was fully revalidated.

## Phase 3A V2 Stage 2 observations

- The existing pipeline already provided JSONL processing, validation, UTC conversion, rejected-event storage, raw preservation and duplicate protection.
- Compound sources such as `identity_risk` were initially reduced to the first filename word. Source identification was corrected to recognise the complete source name.
- The tracked schema and existing database both required updating. A repeatable migration extended the database without removing Phase 3 data.
- Six V2 source files produced 14 records. Twelve were accepted and two malformed records were quarantined.
- Repeated imports accepted zero duplicate events.
- The first V2 validator counted repeated copies of the same malformed input. It was corrected to count distinct malformed evidence.
- The original validator required exactly five source types. It was corrected to preserve those sources while allowing approved V2 additions.
- A temporary unreadable file confirmed that file-level failures are recorded as failed batches.
- A source-only repository copy lacked ignored Stage 7–10 runtime evidence required by older tests. Sanitised test fixtures were added so all 98 unit tests can run without those runtime outputs.
