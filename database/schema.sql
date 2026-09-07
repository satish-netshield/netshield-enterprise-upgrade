CREATE TABLE IF NOT EXISTS system_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_roles (
    username TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
        CHECK (active IN (0, 1))
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_time TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    result TEXT NOT NULL,
    details TEXT
);

CREATE TABLE IF NOT EXISTS import_batches (
    batch_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    source_file TEXT NOT NULL,
    source_type TEXT NOT NULL,
    total_records INTEGER NOT NULL DEFAULT 0,
    accepted_records INTEGER NOT NULL DEFAULT 0,
    rejected_records INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL
        CHECK (
            status IN (
                'started',
                'completed',
                'completed_with_rejections',
                'failed'
            )
        )
);

CREATE TABLE IF NOT EXISTS security_events (
    event_key INTEGER PRIMARY KEY AUTOINCREMENT,
    source_event_id TEXT NOT NULL,
    schema_version TEXT NOT NULL DEFAULT '1.0',
    source_system TEXT NOT NULL DEFAULT 'unknown',
    event_time TEXT NOT NULL,
    received_time TEXT NOT NULL,
    source_type TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT,
    risk_score REAL,
    decision TEXT,
    device_id TEXT,
    asset_id TEXT,
    application_id TEXT,
    service_id TEXT,
    finding_id TEXT,
    incident_id TEXT,
    action_id TEXT,
    username TEXT,
    ip_address TEXT,
    mac_address TEXT,
    hostname TEXT,
    process_name TEXT,
    cpu_percent REAL,
    location TEXT,
    status TEXT,
    message TEXT,
    source_file TEXT NOT NULL,
    batch_id TEXT NOT NULL,
    raw_event TEXT NOT NULL,
    UNIQUE (source_file, source_event_id),
    FOREIGN KEY (batch_id) REFERENCES import_batches(batch_id)
);

CREATE TABLE IF NOT EXISTS rejected_events (
    rejection_id INTEGER PRIMARY KEY AUTOINCREMENT,
    rejected_at TEXT NOT NULL,
    source_file TEXT NOT NULL,
    batch_id TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    reason TEXT NOT NULL,
    quarantine_status TEXT NOT NULL DEFAULT 'quarantined',
    raw_event TEXT NOT NULL,
    FOREIGN KEY (batch_id) REFERENCES import_batches(batch_id)
);

CREATE TABLE IF NOT EXISTS identity_alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    detection_type TEXT NOT NULL,
    severity TEXT NOT NULL
        CHECK (
            severity IN (
                'Low',
                'Medium',
                'High',
                'Critical'
            )
        ),
    username TEXT NOT NULL,
    first_event_time TEXT NOT NULL,
    last_event_time TEXT NOT NULL,
    source_event_ids TEXT NOT NULL,
    ip_address TEXT,
    hostname TEXT,
    location TEXT,
    evidence TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New'
        CHECK (
            status IN (
                'New',
                'Investigating',
                'Confirmed',
                'False Positive',
                'Closed'
            )
        ),
    classification TEXT,
    investigation_notes TEXT
);

CREATE TABLE IF NOT EXISTS network_alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    detection_type TEXT NOT NULL,
    severity TEXT NOT NULL
        CHECK (
            severity IN (
                'Low',
                'Medium',
                'High',
                'Critical'
            )
        ),
    first_event_time TEXT NOT NULL,
    last_event_time TEXT NOT NULL,
    source_event_ids TEXT NOT NULL,
    source_types TEXT NOT NULL,
    ip_address TEXT,
    mac_address TEXT,
    hostname TEXT,
    username TEXT,
    location TEXT,
    evidence TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New'
        CHECK (
            status IN (
                'New',
                'Investigating',
                'Confirmed',
                'False Positive',
                'Closed'
            )
        ),
    classification TEXT,
    investigation_notes TEXT
);

CREATE TABLE IF NOT EXISTS endpoint_alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    detection_type TEXT NOT NULL,
    severity TEXT NOT NULL
        CHECK (
            severity IN (
                'Low',
                'Medium',
                'High',
                'Critical'
            )
        ),
    first_event_time TEXT NOT NULL,
    last_event_time TEXT NOT NULL,
    source_event_ids TEXT NOT NULL,
    source_types TEXT NOT NULL,
    ip_address TEXT,
    mac_address TEXT,
    hostname TEXT,
    username TEXT,
    location TEXT,
    process_name TEXT,
    cpu_percent REAL,
    evidence TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New'
        CHECK (
            status IN (
                'New',
                'Investigating',
                'Confirmed',
                'False Positive',
                'Closed'
            )
        ),
    classification TEXT,
    investigation_notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_security_events_schema_version
ON security_events(schema_version);

CREATE INDEX IF NOT EXISTS idx_security_events_source
ON security_events(source_type, source_system);

CREATE INDEX IF NOT EXISTS idx_security_events_device
ON security_events(device_id);

CREATE INDEX IF NOT EXISTS idx_security_events_incident
ON security_events(incident_id);

CREATE INDEX IF NOT EXISTS idx_security_events_time
ON security_events(event_time);

CREATE INDEX IF NOT EXISTS idx_security_events_type
ON security_events(event_type);

CREATE INDEX IF NOT EXISTS idx_security_events_username
ON security_events(username);

CREATE INDEX IF NOT EXISTS idx_security_events_ip
ON security_events(ip_address);

CREATE INDEX IF NOT EXISTS idx_security_events_mac
ON security_events(mac_address);

CREATE INDEX IF NOT EXISTS idx_identity_alerts_type
ON identity_alerts(detection_type);

CREATE INDEX IF NOT EXISTS idx_identity_alerts_username
ON identity_alerts(username);

CREATE INDEX IF NOT EXISTS idx_identity_alerts_severity
ON identity_alerts(severity);

CREATE INDEX IF NOT EXISTS idx_identity_alerts_status
ON identity_alerts(status);

CREATE INDEX IF NOT EXISTS idx_network_alerts_type
ON network_alerts(detection_type);

CREATE INDEX IF NOT EXISTS idx_network_alerts_severity
ON network_alerts(severity);

CREATE INDEX IF NOT EXISTS idx_network_alerts_status
ON network_alerts(status);

CREATE INDEX IF NOT EXISTS idx_network_alerts_mac
ON network_alerts(mac_address);

CREATE INDEX IF NOT EXISTS idx_network_alerts_ip
ON network_alerts(ip_address);

CREATE INDEX IF NOT EXISTS idx_endpoint_alerts_type
ON endpoint_alerts(detection_type);

CREATE INDEX IF NOT EXISTS idx_endpoint_alerts_severity
ON endpoint_alerts(severity);

CREATE INDEX IF NOT EXISTS idx_endpoint_alerts_status
ON endpoint_alerts(status);

CREATE INDEX IF NOT EXISTS idx_endpoint_alerts_mac
ON endpoint_alerts(mac_address);

CREATE INDEX IF NOT EXISTS idx_endpoint_alerts_ip
ON endpoint_alerts(ip_address);

CREATE INDEX IF NOT EXISTS idx_endpoint_alerts_hostname
ON endpoint_alerts(hostname);

CREATE INDEX IF NOT EXISTS idx_endpoint_alerts_username
ON endpoint_alerts(username);

CREATE INDEX IF NOT EXISTS idx_endpoint_alerts_process
ON endpoint_alerts(process_name);

CREATE INDEX IF NOT EXISTS idx_endpoint_alerts_cpu
ON endpoint_alerts(cpu_percent);

CREATE INDEX IF NOT EXISTS idx_endpoint_alerts_time
ON endpoint_alerts(first_event_time);
