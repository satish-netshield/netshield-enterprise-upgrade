# Engineering Handbook

## Stage 1 — Environment and Access Control

Stage 1 creates the controlled foundation required by every later detection and response component.

## What was built

The project now has:

- A structured Python project
- A local SQLite database
- Separate application and audit logs
- RBAC permissions
- An automation-action ACL
- CYOD and IP access lists
- Protected evidence storage
- Unit tests and a complete Stage 1 validator

## Why the controls exist

Security automation can cause disruption if it is allowed to perform unrestricted actions.

The project separates low-risk evidence and alert actions from actions that affect accounts, devices, processes, firewalls or physical infrastructure.

Default deny ensures that a missing rule does not accidentally become permission.

## Standard library first

Stage 1 uses the Python standard library. This keeps the foundation small and makes its behaviour easier to inspect.

## SQLite

SQLite provides structured local storage without requiring a separate database server.

It suits this single-VM lab, although a larger deployment would require a more scalable database platform.

## Separate audit logging

Application logs explain how the program is operating.

Audit logs record security-relevant actions and accountability. Keeping them separate supports investigation.

## CYOD

CYOD provides a defined approved-device inventory.

An observed device can be compared with its registered MAC address, hostname, user and approval status.

## Evidence hashing

SHA-256 creates a repeatable fingerprint of evidence content.

If the recalculated hash differs from the stored hash, the evidence has changed since preservation.

## What testing proved

Testing confirmed that:

- Approved permissions are allowed.
- Unauthorised permissions are denied.
- Unknown roles are denied.
- Disruptive actions require approval.
- Undefined actions are denied.
- The approved CYOD device is recognised.
- An unknown device is rejected.
- Allowed and unknown IP addresses are classified.
- Malformed IP input raises an error.
- The database and logs operate correctly.
- Sensitive filesystem permissions are applied.
- Evidence integrity can be verified.

## Important limitation

Application RBAC controls project decisions but does not create separate Linux operating-system users.

The Wi-Fi heat-map scenario will also require simulated signal data because the VM uses a virtual network adapter.

## What comes next

Stage 2 will generate, import, validate and normalise security events before storing them for detection.
