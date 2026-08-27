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
- Invalid IP, missing event ID, invalid JSON and CPU values above 100 were rejected.
- Duplicate-event protection was confirmed with an isolated temporary database.
- All 28 Stage 1 and Stage 2 unit tests passed.
- Stage 1 validation remained 12/12.
- Stage 2 validation passed 14/14.

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
- Stage 3 validation passed 12/12.
- The full Stage 3 regression run passed 39 tests.

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
- Stage 4 validation passed 12/12.
- The complete regression run passed 44 tests.

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
- Stage 5 validation passed 12/12.
- The complete Stage 1–5 regression run passed 52 tests.

## Stage 6 observations

- Stage 6 was created as a separate local SQL injection lab.
- The lab uses a separate SQLite database and one test account.
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
- Stage 6 validation passed 15/15.

## Stage 7 observations

- Stage 7 used seven controlled correlation events.
- The events represented authentication, network, endpoint and application activity.
- Four events sharing identity fields and a time window were combined into one incident.
- The main incident contained four source types and received a Critical score of 30.
- An approved-device and known-VPN group received a Low score of 1.
- One isolated medium network event was initially scored too strongly.
- Isolated low-value activity was reduced to Low with a score of 3.
- The first IoC extraction included the username.
- The extraction logic was corrected so usernames remain incident context.
- The corrected main incident contained four IoCs: IP address, MAC address, hostname and process name.
- Repeated failed logins and repeated connection attempts remained behaviours rather than IoCs.
- Approved-device and known-VPN exceptions reduced risk without removing the original evidence.
- Three incidents were created from seven events.
- Five Stage 7 correlation tests passed.
- Stage 7 validation passed 15/15.
- Automatic containment remained disabled.

## Engineering lessons

- A result must be checked against the underlying evidence, not only a summary line.
- Source validation must happen before correlation.
- A detection is evidence for investigation, not automatic proof of compromise.
- Approved activity must be represented in test data so it is not incorrectly reported.
- A MAC address, username or source IP should not be treated as complete proof of identity.
- Several related indicators can provide stronger context than one isolated alert.
- IoCs and behaviours have different meanings and should remain separate.
- Clean-run data is important because cumulative logs can produce misleading totals.
- Each genuine test failure should be corrected and retested before sign-off.
- The next response stage can build on the Stage 7 incidents, scores and preserved evidence.
