# Notes from Testing

## Stage 1 observations

- Ubuntu 26.04 LTS included Python 3.14.4, Git 2.53.0 and SQLite 3.46.1.
- The Python virtual environment was created without third-party packages.
- The VirtualBox NAT interface was registered as the first approved CYOD test device.
- All three Stage 1 JSON configuration files passed parsing validation.
- The initialisation script created the database, metadata, role assignment and audit records.
- Application and security audit activity are written to separate logs.
- Eleven unit tests passed for RBAC, automation ACL, CYOD and IP decisions.
- The complete Stage 1 validator passed all 12 checks.
- The sample evidence file passed SHA-256 integrity verification after being changed to read-only.

## Stage 2 observations

- Stage 2 continued using only the Python standard library.
- Five source files generated 19 controlled test records.
- Fifteen valid records were accepted into SQLite.
- Four deliberately malformed records were rejected.
- Each source type stored three accepted events.
- The authentication record without an event ID was rejected.
- The network record containing `999.10.10.10` was rejected.
- Endpoint CPU usage of 145 percent was rejected.
- The invalid application JSON line was rejected during parsing.
- Rejected input retained its filename, line number, original content and failure reason.
- New Zealand timestamps using `+12:00` were converted to UTC.
- The approved CYOD MAC address remained `08:00:27:cf:49:71`.
- The controlled CPU stress-test value of 91.7 percent was accepted.
- Duplicate protection was tested using an isolated temporary database.
- Import-batch totals were checked to confirm that total equals accepted plus rejected.
- All 28 current unit tests passed.
- Stage 1 still passed all 12 validation checks after the pipeline changes.
- The Stage 2 validator passed all 14 checks.

## Rejected test records

| Source file | Line | Reason |
| --- | ---: | --- |
| `application_events.jsonl` | 4 | Invalid JSON |
| `authentication_events.jsonl` | 4 | Missing event ID |
| `endpoint_events.jsonl` | 4 | CPU percentage above 100 |
| `network_events.jsonl` | 4 | Invalid IP address |

These records were deliberately created to test rejection handling. They did not enter the accepted security-event table.

## Engineering decisions

### JSONL input

JSON Lines stores one JSON object on each line.

One malformed line can be rejected without stopping the remaining records in the file.

### SQLite storage

Accepted events are stored in SQLite instead of being copied into another generated text file.

The `data/processed` directory remains available for later exports.

### UTC timestamps

Source timestamps are converted to UTC before storage.

This gives later detection and correlation stages one timeline across sources and locations.

### Source verification

The source type inside an event must match its filename.

A mismatched event is preserved as rejected input rather than trusted automatically.

### Rejected input

Rejected records are kept with clear failure reasons instead of being deleted.

This supports troubleshooting and shows exactly why an event was not accepted.

### Duplicate handling

A duplicate event is not silently inserted or counted as accepted.

The first event remains in the accepted table. A repeated source event is recorded as rejected.

### Raw and normalised data

Accepted events keep their original JSON and their normalised fields.

The original context remains available while the normalised fields support consistent searches.

## Practical decisions

The VirtualBox interface can test device-inventory logic but cannot provide physical Wi-Fi location data. Wireless signal and heat-map events use controlled simulated data.

The network test events use documentation IP ranges. They are not real attack targets.

Runtime databases, logs, reports and evidence are excluded from Git. Safe simulated source events are tracked because they are reproducible project test inputs.

Running an initialisation script again creates another audit event. This preserves the activity history instead of overwriting it.

## Known limitations

- Stage 2 uses generated events instead of live log feeds.
- The collector currently processes local JSONL files only.
- Application RBAC does not replace Linux user isolation.
- MAC addresses can be spoofed.
- The CYOD allowlist currently contains one local test asset.
- The blocklist is simulated and does not modify the firewall.
- Read-only evidence can still be changed by a sufficiently privileged administrator.
- SQLite is a single-host database and does not provide distributed scaling.
- Detection thresholds and alert creation begin in later stages.
