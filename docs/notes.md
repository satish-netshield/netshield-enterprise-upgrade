# Notes from Testing

## Stage 1 observations

- Ubuntu 26.04 LTS included Python 3.14.4, Git 2.53.0 and SQLite 3.46.1.
- The Python virtual environment was created without third-party packages.
- The VirtualBox NAT interface was registered as the first approved CYOD test device.
- All three JSON configuration files passed parsing validation.
- The initialisation script created the database, metadata, role assignment and audit records.
- Application and security audit activity are written to separate logs.
- Eleven unit tests passed for RBAC, automation ACL, CYOD and IP decisions.
- The complete Stage 1 validator passed all 12 checks.
- The sample evidence file passed SHA-256 integrity verification after being changed to read-only.

## Practical decisions

The VirtualBox interface can test device-inventory logic, but it cannot provide physical Wi-Fi location data. Wireless signal and heat-map events will use controlled simulated data.

Runtime databases, logs, reports and evidence are excluded from Git. Their empty directories are retained using `.gitkeep` files.

Running the initialisation script again creates another audit event. This preserves the history of repeated initialisation rather than overwriting the earlier record.

## Known limitations

- Application RBAC does not replace Linux user isolation.
- MAC addresses can be spoofed.
- The allowlist currently contains one local test asset.
- The blocklist is simulated and does not modify the firewall.
- Read-only evidence can still be changed by a sufficiently privileged administrator.
