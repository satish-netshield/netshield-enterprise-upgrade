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

CREATE TABLE IF NOT EXISTS device_inventory (
    inventory_id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id TEXT NOT NULL UNIQUE,
    device_id TEXT NOT NULL UNIQUE,
    hostname TEXT NOT NULL,
    assigned_user TEXT,
    ownership TEXT NOT NULL,
    device_type TEXT NOT NULL,
    manufacturer TEXT NOT NULL,
    operating_system TEXT NOT NULL,
    os_version TEXT,
    mac_address TEXT,
    ip_address TEXT,
    location TEXT,
    connection_type TEXT,
    registration_status TEXT NOT NULL
        CHECK (
            registration_status IN (
                'registered',
                'unregistered',
                'removed'
            )
        ),
    compliance_status TEXT NOT NULL
        CHECK (
            compliance_status IN (
                'compliant',
                'non_compliant',
                'unknown'
            )
        ),
    risk_status TEXT NOT NULL
        CHECK (
            risk_status IN (
                'low',
                'medium',
                'high',
                'critical',
                'unknown'
            )
        ),
    criticality TEXT NOT NULL
        CHECK (
            criticality IN (
                'low',
                'medium',
                'high',
                'critical'
            )
        ),
    registered_date TEXT,
    last_seen TEXT
);

CREATE TABLE IF NOT EXISTS device_alerts (
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
    device_id TEXT,
    asset_id TEXT,
    hostname TEXT,
    username TEXT,
    ip_address TEXT,
    mac_address TEXT,
    location TEXT,
    source_event_ids TEXT NOT NULL,
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

CREATE TABLE IF NOT EXISTS device_registration_history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_time TEXT NOT NULL,
    device_id TEXT NOT NULL,
    asset_id TEXT,
    action TEXT NOT NULL
        CHECK (
            action IN (
                'register',
                'update',
                'remove'
            )
        ),
    previous_status TEXT,
    new_status TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_device_inventory_device
ON device_inventory(device_id);

CREATE INDEX IF NOT EXISTS idx_device_inventory_asset
ON device_inventory(asset_id);

CREATE INDEX IF NOT EXISTS idx_device_inventory_hostname
ON device_inventory(hostname);

CREATE INDEX IF NOT EXISTS idx_device_inventory_user
ON device_inventory(assigned_user);

CREATE INDEX IF NOT EXISTS idx_device_inventory_registration
ON device_inventory(registration_status);

CREATE INDEX IF NOT EXISTS idx_device_inventory_compliance
ON device_inventory(compliance_status);

CREATE INDEX IF NOT EXISTS idx_device_inventory_risk
ON device_inventory(risk_status);

CREATE INDEX IF NOT EXISTS idx_device_inventory_last_seen
ON device_inventory(last_seen);

CREATE INDEX IF NOT EXISTS idx_device_alerts_type
ON device_alerts(detection_type);

CREATE INDEX IF NOT EXISTS idx_device_alerts_device
ON device_alerts(device_id);

CREATE INDEX IF NOT EXISTS idx_device_alerts_status
ON device_alerts(status);

CREATE INDEX IF NOT EXISTS idx_device_registration_device
ON device_registration_history(device_id);

CREATE TABLE IF NOT EXISTS v2_identity_alerts (
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
    confidence INTEGER NOT NULL
        CHECK (confidence BETWEEN 0 AND 100),
    username TEXT NOT NULL,
    device_id TEXT,
    first_event_time TEXT NOT NULL,
    last_event_time TEXT NOT NULL,
    source_event_ids TEXT NOT NULL,
    source_types TEXT NOT NULL,
    ip_address TEXT,
    location TEXT,
    risk_score REAL
        CHECK (
            risk_score IS NULL
            OR risk_score BETWEEN 0 AND 100
        ),
    reason_codes TEXT NOT NULL,
    mitre_techniques TEXT NOT NULL,
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

CREATE TABLE IF NOT EXISTS temporary_access_restrictions (
    restriction_id INTEGER PRIMARY KEY AUTOINCREMENT,
    restriction_key TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    active INTEGER NOT NULL DEFAULT 1
        CHECK (active IN (0, 1)),
    reason TEXT NOT NULL,
    actor TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_policy_decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_key TEXT NOT NULL UNIQUE,
    evaluated_at TEXT NOT NULL,
    request_event_id TEXT NOT NULL,
    username TEXT,
    role TEXT,
    device_id TEXT,
    application_id TEXT,
    asset_id TEXT,
    asset_criticality TEXT,
    location TEXT,
    ip_address TEXT,
    sign_in_risk REAL
        CHECK (
            sign_in_risk IS NULL
            OR sign_in_risk BETWEEN 0 AND 100
        ),
    user_risk REAL
        CHECK (
            user_risk IS NULL
            OR user_risk BETWEEN 0 AND 100
        ),
    mfa_satisfied INTEGER NOT NULL
        CHECK (mfa_satisfied IN (0, 1)),
    decision TEXT NOT NULL
        CHECK (
            decision IN (
                'allow',
                'deny',
                'challenge',
                'restrict'
            )
        ),
    reason_codes TEXT NOT NULL,
    matched_policy_ids TEXT NOT NULL,
    winning_policy_id TEXT,
    identity_evidence TEXT NOT NULL,
    device_evidence TEXT NOT NULL,
    risk_evidence TEXT NOT NULL,
    response_action TEXT,
    acl_control_level TEXT,
    response_status TEXT NOT NULL,
    evidence TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_v2_identity_alerts_type
ON v2_identity_alerts(detection_type);

CREATE INDEX IF NOT EXISTS idx_v2_identity_alerts_username
ON v2_identity_alerts(username);

CREATE INDEX IF NOT EXISTS idx_v2_identity_alerts_device
ON v2_identity_alerts(device_id);

CREATE INDEX IF NOT EXISTS idx_v2_identity_alerts_severity
ON v2_identity_alerts(severity);

CREATE INDEX IF NOT EXISTS idx_v2_identity_alerts_status
ON v2_identity_alerts(status);

CREATE INDEX IF NOT EXISTS idx_v2_identity_alerts_time
ON v2_identity_alerts(first_event_time, last_event_time);

CREATE INDEX IF NOT EXISTS idx_access_restrictions_username
ON temporary_access_restrictions(username);

CREATE INDEX IF NOT EXISTS idx_access_restrictions_active
ON temporary_access_restrictions(active);

CREATE INDEX IF NOT EXISTS idx_access_policy_request
ON access_policy_decisions(request_event_id);

CREATE INDEX IF NOT EXISTS idx_access_policy_username
ON access_policy_decisions(username);

CREATE INDEX IF NOT EXISTS idx_access_policy_device
ON access_policy_decisions(device_id);

CREATE INDEX IF NOT EXISTS idx_access_policy_application
ON access_policy_decisions(application_id);

CREATE INDEX IF NOT EXISTS idx_access_policy_decision
ON access_policy_decisions(decision);

CREATE INDEX IF NOT EXISTS idx_access_policy_time
ON access_policy_decisions(evaluated_at);
