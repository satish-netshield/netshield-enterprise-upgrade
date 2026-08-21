# Notes from Testing

## Stage 1 observations

- Ubuntu 26.04 LTS provided Python 3.14.4, Git 2.53.0 and SQLite 3.46.1.
- The VirtualBox NAT interface was registered as the first approved CYOD test asset.
- Eleven access-control tests passed.
- Stage 1 validation passed all 12 checks.
- SHA-256 evidence verification passed after the preserved file was made read-only.

## Stage 2 observations

- Five simulated JSONL sources produced 19 records.
- Fifteen records were accepted and four deliberately malformed records were rejected.
- Rejected records retained their filename, line number, original input and failure reason.
- Timestamps with a `+12:00` offset were converted to UTC.
- Invalid IP, missing event ID, invalid JSON and CPU values above 100 were rejected.
- Duplicate-event protection was confirmed with an isolated temporary database.
- All 28 Stage 1 and Stage 2 unit tests passed.
- Stage 1 validation remained 12/12 after the pipeline was added.
- Stage 2 validation passed 14/14.

## Stage 3 observations

- Sixteen simulated authentication events were imported successfully.
- The identity detector created 11 alerts from 19 accepted authentication events.
- The detector identified repeated failures, possible brute force, successful login after failures, MFA anomalies, new devices, unusual locations, impossible travel and a suspicious role change.
- A second detector run created zero new alerts and counted 11 existing alerts.
- Two approved VPN events were recorded as exceptions.
- The Stage 2 validator initially failed after Stage 3 added authentication events because it counted all authentication records.
- The validator was corrected to check only the original Stage 2 source files.
- After the correction, Stage 2 validation passed 14/14 again.
- The replacement laptop generated a new-device alert because it was authorised but not yet registered in the CYOD inventory.
- The replacement-device alert was preserved and classified as a false positive with an audit record.
- Eleven Stage 3 detector tests passed.
- Stage 3 validation passed 12/12.
- The full regression run passed 39 tests.

## Rejected records

Stage 2 deliberately rejected:

| Source | Problem |
| --- | --- |
| Application | Invalid JSON |
| Authentication | Missing event ID |
| Endpoint | CPU percentage above 100 |
| Network | Invalid IP address |

These records remained available for troubleshooting and did not enter the accepted-event table.

## Engineering decisions

- JSONL was used because one malformed line can be rejected without stopping the complete file.
- UTC storage was used so events from different locations can share one timeline.
- Source-type verification prevents incorrectly labelled data from entering detection.
- Parameterised SQL treats event values as data rather than SQL instructions.
- Original JSON is preserved alongside normalised fields for investigation.
- A deterministic alert key prevents repeated detector runs from flooding the alert table.
- Known VPN addresses are exceptions for selected baseline and travel checks.
- A new-device alert is investigated rather than automatically treated as malicious.
- An approved replacement device should be registered in the CYOD inventory after verification.
- Duplicate protection needs future last-seen tracking and escalation for unresolved conditions.
- A shorter authentication failure window may be more realistic than the current five-minute test window.
- Impossible travel combined with MFA failures, brute force or unauthorised privilege escalation should receive stronger severity.
- Wi-Fi zones, device consistency and WPA3 posture will be added during network and CYOD detection.

## Practical decisions

- VirtualBox can test inventory logic but cannot provide real physical Wi-Fi heat-map data.
- Wireless and location scenarios therefore use controlled simulated events.
- Documentation IP ranges are used for safe local testing.
- Runtime databases, logs and evidence remain excluded from Git.
- Re-running initialisation records another audit event rather than overwriting history.
- Stage 3 changes were tested without changing the validated Stage 1 foundation.

## Known limitations

- Stage 2 and Stage 3 use local simulated events rather than live feeds.
- The CYOD inventory contains one primary local test asset.
- The VPN exception is simulated and does not represent a production VPN.
- MAC addresses can be spoofed.
- Ping and traceroute do not prove a user’s physical location.
- Alert-key deduplication does not yet track unresolved inventory conditions over time.
- SQLite is suitable for this single-VM lab but not distributed scaling.
- Stage 3 assigns initial rule-based severity; later correlation will reassess combined risk.
