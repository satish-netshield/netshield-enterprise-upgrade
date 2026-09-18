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

CREATE TABLE IF NOT EXISTS v2_network_alerts (
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
        CHECK (
            confidence BETWEEN 0 AND 100
        ),
    first_event_time TEXT NOT NULL,
    last_event_time TEXT NOT NULL,
    source_event_ids TEXT NOT NULL,
    source_types TEXT NOT NULL,
    device_id TEXT,
    asset_id TEXT,
    username TEXT,
    ip_address TEXT,
    mac_address TEXT,
    hostname TEXT,
    location TEXT,
    connection_type TEXT,
    destination_ip TEXT,
    destination_port INTEGER,
    service TEXT,
    reason_codes TEXT NOT NULL,
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
    investigation_notes TEXT,
    reviewed_by TEXT,
    reviewed_at TEXT
);

CREATE TABLE IF NOT EXISTS v2_network_access_decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_key TEXT NOT NULL UNIQUE,
    evaluated_at TEXT NOT NULL,
    source_event_id TEXT NOT NULL UNIQUE,
    event_time TEXT NOT NULL,
    source_type TEXT NOT NULL,
    event_type TEXT NOT NULL,
    device_id TEXT,
    asset_id TEXT,
    username TEXT,
    ip_address TEXT,
    mac_address TEXT,
    hostname TEXT,
    location TEXT,
    connection_type TEXT,
    destination_ip TEXT,
    destination_port INTEGER,
    service TEXT,
    decision TEXT NOT NULL
        CHECK (
            decision IN (
                'allow',
                'deny',
                'challenge',
                'restrict'
            )
        ),
    matching_rules TEXT NOT NULL,
    reason_codes TEXT NOT NULL,
    evidence TEXT NOT NULL,
    response_action TEXT,
    acl_control_level TEXT,
    response_status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_network_connection_timeline (
    timeline_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_event_id TEXT NOT NULL UNIQUE,
    event_time TEXT NOT NULL,
    source_type TEXT NOT NULL,
    event_type TEXT NOT NULL,
    device_id TEXT,
    asset_id TEXT,
    username TEXT,
    ip_address TEXT,
    mac_address TEXT,
    hostname TEXT,
    location TEXT,
    connection_type TEXT,
    destination_ip TEXT,
    destination_port INTEGER,
    service TEXT,
    status TEXT,
    raw_event TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_v2_network_alerts_type
ON v2_network_alerts(detection_type);

CREATE INDEX IF NOT EXISTS idx_v2_network_alerts_severity
ON v2_network_alerts(severity);

CREATE INDEX IF NOT EXISTS idx_v2_network_alerts_status
ON v2_network_alerts(status);

CREATE INDEX IF NOT EXISTS idx_v2_network_alerts_device
ON v2_network_alerts(device_id);

CREATE INDEX IF NOT EXISTS idx_v2_network_alerts_ip
ON v2_network_alerts(ip_address);

CREATE INDEX IF NOT EXISTS idx_v2_network_alerts_mac
ON v2_network_alerts(mac_address);

CREATE INDEX IF NOT EXISTS idx_v2_network_alerts_time
ON v2_network_alerts(first_event_time, last_event_time);

CREATE INDEX IF NOT EXISTS idx_v2_network_decisions_source
ON v2_network_access_decisions(source_event_id);

CREATE INDEX IF NOT EXISTS idx_v2_network_decisions_decision
ON v2_network_access_decisions(decision);

CREATE INDEX IF NOT EXISTS idx_v2_network_decisions_device
ON v2_network_access_decisions(device_id);

CREATE INDEX IF NOT EXISTS idx_v2_network_decisions_ip
ON v2_network_access_decisions(ip_address);

CREATE INDEX IF NOT EXISTS idx_v2_network_decisions_time
ON v2_network_access_decisions(evaluated_at);

CREATE INDEX IF NOT EXISTS idx_v2_network_timeline_source
ON v2_network_connection_timeline(source_event_id);

CREATE INDEX IF NOT EXISTS idx_v2_network_timeline_time
ON v2_network_connection_timeline(event_time);

CREATE INDEX IF NOT EXISTS idx_v2_network_timeline_device
ON v2_network_connection_timeline(device_id);

CREATE INDEX IF NOT EXISTS idx_v2_network_timeline_ip
ON v2_network_connection_timeline(ip_address);

CREATE INDEX IF NOT EXISTS idx_v2_network_timeline_mac
ON v2_network_connection_timeline(mac_address);

-- Phase 3A V2 Stage 7 endpoint monitoring

CREATE TABLE IF NOT EXISTS v2_endpoint_activity_timeline (
    timeline_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_event_id TEXT NOT NULL UNIQUE,
    event_time TEXT NOT NULL,
    source_type TEXT NOT NULL,
    event_type TEXT NOT NULL,
    device_id TEXT,
    asset_id TEXT,
    username TEXT,
    hostname TEXT,
    ip_address TEXT,
    mac_address TEXT,
    location TEXT,
    health_state TEXT,
    compliance_state TEXT,
    device_risk_state TEXT,
    process_name TEXT,
    process_id INTEGER,
    process_owner TEXT,
    parent_process_name TEXT,
    command_line TEXT,
    cpu_percent REAL,
    file_path TEXT,
    observed_hash TEXT,
    isolation_state TEXT,
    status TEXT,
    raw_event TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_endpoint_alerts (
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
        CHECK (
            confidence BETWEEN 0 AND 100
        ),
    first_event_time TEXT NOT NULL,
    last_event_time TEXT NOT NULL,
    source_event_ids TEXT NOT NULL,
    source_types TEXT NOT NULL,
    device_id TEXT,
    asset_id TEXT,
    username TEXT,
    hostname TEXT,
    ip_address TEXT,
    mac_address TEXT,
    location TEXT,
    health_state TEXT,
    compliance_state TEXT,
    device_risk_state TEXT,
    process_name TEXT,
    process_id INTEGER,
    process_owner TEXT,
    parent_process_name TEXT,
    command_line TEXT,
    cpu_percent REAL,
    file_path TEXT,
    expected_hash TEXT,
    observed_hash TEXT,
    reason_codes TEXT NOT NULL,
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
    investigation_notes TEXT,
    reviewed_by TEXT,
    reviewed_at TEXT
);

CREATE TABLE IF NOT EXISTS v2_endpoint_isolation_actions (
    isolation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    isolation_key TEXT NOT NULL UNIQUE,
    alert_key TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    device_id TEXT NOT NULL,
    asset_id TEXT,
    action TEXT NOT NULL
        CHECK (
            action = 'quarantine_device'
        ),
    acl_control_level TEXT NOT NULL
        CHECK (
            acl_control_level = 'approval_required'
        ),
    status TEXT NOT NULL
        CHECK (
            status IN (
                'approval_required',
                'simulated_isolated',
                'rejected'
            )
        ),
    request_reason TEXT NOT NULL,
    approved_by TEXT,
    approved_at TEXT,
    network_state_changed INTEGER NOT NULL DEFAULT 0
        CHECK (
            network_state_changed = 0
        ),
    real_action_executed INTEGER NOT NULL DEFAULT 0
        CHECK (
            real_action_executed = 0
        ),
    evidence TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_alerts_asset
ON v2_endpoint_alerts(asset_id);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_alerts_device
ON v2_endpoint_alerts(device_id);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_alerts_process
ON v2_endpoint_alerts(process_name);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_alerts_severity
ON v2_endpoint_alerts(severity);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_alerts_status
ON v2_endpoint_alerts(status);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_alerts_time
ON v2_endpoint_alerts(first_event_time, last_event_time);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_alerts_type
ON v2_endpoint_alerts(detection_type);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_isolation_device
ON v2_endpoint_isolation_actions(device_id);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_isolation_requested
ON v2_endpoint_isolation_actions(requested_at);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_isolation_status
ON v2_endpoint_isolation_actions(status);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_timeline_asset
ON v2_endpoint_activity_timeline(asset_id);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_timeline_device
ON v2_endpoint_activity_timeline(device_id);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_timeline_isolation
ON v2_endpoint_activity_timeline(isolation_state);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_timeline_process
ON v2_endpoint_activity_timeline(process_name);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_timeline_source
ON v2_endpoint_activity_timeline(source_event_id);

CREATE INDEX IF NOT EXISTS idx_v2_endpoint_timeline_time
ON v2_endpoint_activity_timeline(event_time);

-- Phase 3A V2 Stage 8 vulnerability management

CREATE TABLE IF NOT EXISTS v2_vulnerability_findings (
    finding_record_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_key TEXT NOT NULL UNIQUE,
    source_finding_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    title TEXT NOT NULL,
    finding_source TEXT NOT NULL,
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
        CHECK (
            confidence BETWEEN 0 AND 100
        ),
    confidence_level TEXT NOT NULL
        CHECK (
            confidence_level IN (
                'Low',
                'Medium',
                'High',
                'Very High'
            )
        ),
    exploitability TEXT NOT NULL
        CHECK (
            exploitability IN (
                'none',
                'low',
                'medium',
                'high',
                'demonstrated'
            )
        ),
    exploitation_status TEXT NOT NULL DEFAULT 'none'
        CHECK (
            exploitation_status IN (
                'none',
                'attempted',
                'successful'
            )
        ),
    exposure_level TEXT NOT NULL
        CHECK (
            exposure_level IN (
                'none',
                'internal',
                'restricted',
                'exposed',
                'internet_facing'
            )
        ),
    exposed_service TEXT,
    asset_criticality TEXT NOT NULL
        CHECK (
            asset_criticality IN (
                'low',
                'medium',
                'high',
                'critical'
            )
        ),
    priority_score REAL NOT NULL
        CHECK (
            priority_score BETWEEN 0 AND 100
        ),
    priority_level TEXT NOT NULL
        CHECK (
            priority_level IN (
                'Low',
                'Medium',
                'High',
                'Critical'
            )
        ),
    component_name TEXT,
    component_version TEXT,
    safe_check TEXT NOT NULL,
    source_event_ids TEXT NOT NULL,
    reason_codes TEXT NOT NULL,
    evidence TEXT NOT NULL,
    remediation_status TEXT NOT NULL
        CHECK (
            remediation_status IN (
                'Open',
                'Planned',
                'In Progress',
                'Remediated',
                'Verified',
                'False Positive'
            )
        ),
    verification_status TEXT,
    verified_at TEXT,
    classification TEXT,
    investigation_notes TEXT,
    reviewed_by TEXT,
    reviewed_at TEXT
);

CREATE TABLE IF NOT EXISTS v2_vulnerability_links (
    link_id INTEGER PRIMARY KEY AUTOINCREMENT,
    link_key TEXT NOT NULL UNIQUE,
    finding_key TEXT NOT NULL,
    source_finding_id TEXT NOT NULL,
    link_type TEXT NOT NULL
        CHECK (
            link_type IN (
                'alert',
                'incident'
            )
        ),
    linked_record_id TEXT NOT NULL,
    exploitation_status TEXT NOT NULL DEFAULT 'none'
        CHECK (
            exploitation_status IN (
                'none',
                'attempted',
                'successful'
            )
        ),
    created_at TEXT NOT NULL,
    evidence TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_vulnerability_remediation_history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
    history_key TEXT NOT NULL UNIQUE,
    finding_key TEXT NOT NULL,
    source_finding_id TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    previous_status TEXT,
    new_status TEXT NOT NULL,
    verification_result TEXT,
    evidence TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_findings_asset
ON v2_vulnerability_findings(asset_id);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_findings_priority
ON v2_vulnerability_findings(priority_level, priority_score);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_findings_severity
ON v2_vulnerability_findings(severity);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_findings_source
ON v2_vulnerability_findings(source_finding_id);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_findings_status
ON v2_vulnerability_findings(remediation_status);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_findings_type
ON v2_vulnerability_findings(finding_type);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_findings_updated
ON v2_vulnerability_findings(updated_at);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_history_finding
ON v2_vulnerability_remediation_history(finding_key);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_history_status
ON v2_vulnerability_remediation_history(new_status);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_history_time
ON v2_vulnerability_remediation_history(recorded_at);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_links_finding
ON v2_vulnerability_links(finding_key);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_links_record
ON v2_vulnerability_links(linked_record_id);

CREATE INDEX IF NOT EXISTS idx_v2_vulnerability_links_type
ON v2_vulnerability_links(link_type);

-- Phase 3A V2 Stage 9 continuous monitoring

CREATE TABLE IF NOT EXISTS v2_monitoring_cycles (
    cycle_id INTEGER PRIMARY KEY AUTOINCREMENT,
    cycle_key TEXT NOT NULL UNIQUE,
    scheduled_for TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL
        CHECK (
            status IN (
                'running',
                'completed',
                'completed_with_warnings',
                'failed',
                'suppressed_cooldown'
            )
        ),
    ingestion_status TEXT NOT NULL
        CHECK (
            ingestion_status IN (
                'not_started',
                'healthy',
                'degraded',
                'failed',
                'skipped'
            )
        ),
    detection_status TEXT NOT NULL
        CHECK (
            detection_status IN (
                'not_started',
                'healthy',
                'degraded',
                'failed',
                'skipped'
            )
        ),
    risk_status TEXT NOT NULL
        CHECK (
            risk_status IN (
                'not_started',
                'healthy',
                'degraded',
                'failed',
                'skipped'
            )
        ),
    last_successful_run TEXT,
    records_assessed INTEGER NOT NULL DEFAULT 0
        CHECK (records_assessed >= 0),
    entities_scored INTEGER NOT NULL DEFAULT 0
        CHECK (entities_scored >= 0),
    alerts_created INTEGER NOT NULL DEFAULT 0
        CHECK (alerts_created >= 0),
    alerts_suppressed INTEGER NOT NULL DEFAULT 0
        CHECK (alerts_suppressed >= 0),
    metrics TEXT NOT NULL,
    failure_details TEXT
);

CREATE TABLE IF NOT EXISTS v2_continuous_risk_scores (
    risk_id INTEGER PRIMARY KEY AUTOINCREMENT,
    risk_key TEXT NOT NULL UNIQUE,
    entity_type TEXT NOT NULL
        CHECK (
            entity_type IN (
                'user',
                'device',
                'asset',
                'incident'
            )
        ),
    entity_id TEXT NOT NULL,
    assessed_at TEXT NOT NULL,
    risk_score REAL NOT NULL
        CHECK (risk_score BETWEEN 0 AND 100),
    risk_level TEXT NOT NULL
        CHECK (
            risk_level IN (
                'Low',
                'Medium',
                'High',
                'Critical'
            )
        ),
    severity_component REAL NOT NULL,
    confidence_component REAL NOT NULL,
    asset_criticality_component REAL NOT NULL,
    agreement_adjustment REAL NOT NULL,
    exception_adjustment REAL NOT NULL,
    decay_adjustment REAL NOT NULL,
    independent_source_count INTEGER NOT NULL
        CHECK (independent_source_count >= 0),
    source_types TEXT NOT NULL,
    evidence_refs TEXT NOT NULL,
    evidence TEXT NOT NULL,
    last_evidence_time TEXT NOT NULL,
    original_evidence_preserved INTEGER NOT NULL DEFAULT 1
        CHECK (original_evidence_preserved = 1),
    UNIQUE (entity_type, entity_id)
);

CREATE TABLE IF NOT EXISTS v2_continuous_risk_history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
    history_key TEXT NOT NULL UNIQUE,
    cycle_key TEXT NOT NULL,
    entity_type TEXT NOT NULL
        CHECK (
            entity_type IN (
                'user',
                'device',
                'asset',
                'incident'
            )
        ),
    entity_id TEXT NOT NULL,
    assessed_at TEXT NOT NULL,
    previous_score REAL,
    new_score REAL NOT NULL
        CHECK (new_score BETWEEN 0 AND 100),
    previous_level TEXT,
    new_level TEXT NOT NULL
        CHECK (
            new_level IN (
                'Low',
                'Medium',
                'High',
                'Critical'
            )
        ),
    change_reason TEXT NOT NULL,
    source_types TEXT NOT NULL,
    evidence_refs TEXT NOT NULL,
    calculation TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_monitoring_alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_key TEXT NOT NULL UNIQUE,
    alert_type TEXT NOT NULL
        CHECK (
            alert_type IN (
                'risk_threshold',
                'risk_escalation',
                'detection_health',
                'pipeline_failure'
            )
        ),
    created_at TEXT NOT NULL,
    last_observed_at TEXT NOT NULL,
    entity_type TEXT,
    entity_id TEXT,
    component TEXT,
    risk_score REAL
        CHECK (
            risk_score IS NULL
            OR risk_score BETWEEN 0 AND 100
        ),
    threshold REAL,
    severity TEXT NOT NULL
        CHECK (
            severity IN (
                'Low',
                'Medium',
                'High',
                'Critical'
            )
        ),
    status TEXT NOT NULL
        CHECK (
            status IN (
                'New',
                'Monitoring',
                'Suppressed',
                'Closed'
            )
        ),
    cooldown_until TEXT,
    suppression_reason TEXT,
    occurrence_count INTEGER NOT NULL DEFAULT 1
        CHECK (occurrence_count >= 1),
    independent_source_count INTEGER NOT NULL DEFAULT 0
        CHECK (independent_source_count >= 0),
    source_types TEXT NOT NULL,
    evidence_refs TEXT NOT NULL,
    evidence TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_detection_health (
    health_id INTEGER PRIMARY KEY AUTOINCREMENT,
    health_key TEXT NOT NULL UNIQUE,
    cycle_key TEXT NOT NULL,
    component TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (
            status IN (
                'healthy',
                'degraded',
                'failed'
            )
        ),
    last_successful_run TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0
        CHECK (consecutive_failures >= 0),
    records_processed INTEGER NOT NULL DEFAULT 0
        CHECK (records_processed >= 0),
    details TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_v2_monitoring_cycles_scheduled
ON v2_monitoring_cycles(scheduled_for);

CREATE INDEX IF NOT EXISTS idx_v2_monitoring_cycles_status
ON v2_monitoring_cycles(status);

CREATE INDEX IF NOT EXISTS idx_v2_monitoring_cycles_completed
ON v2_monitoring_cycles(completed_at);

CREATE INDEX IF NOT EXISTS idx_v2_monitoring_cycles_last_success
ON v2_monitoring_cycles(last_successful_run);

CREATE INDEX IF NOT EXISTS idx_v2_risk_scores_entity
ON v2_continuous_risk_scores(entity_type, entity_id);

CREATE INDEX IF NOT EXISTS idx_v2_risk_scores_level
ON v2_continuous_risk_scores(risk_level);

CREATE INDEX IF NOT EXISTS idx_v2_risk_scores_score
ON v2_continuous_risk_scores(risk_score);

CREATE INDEX IF NOT EXISTS idx_v2_risk_scores_assessed
ON v2_continuous_risk_scores(assessed_at);

CREATE INDEX IF NOT EXISTS idx_v2_risk_scores_last_evidence
ON v2_continuous_risk_scores(last_evidence_time);

CREATE INDEX IF NOT EXISTS idx_v2_risk_history_entity
ON v2_continuous_risk_history(entity_type, entity_id);

CREATE INDEX IF NOT EXISTS idx_v2_risk_history_cycle
ON v2_continuous_risk_history(cycle_key);

CREATE INDEX IF NOT EXISTS idx_v2_risk_history_time
ON v2_continuous_risk_history(assessed_at);

CREATE INDEX IF NOT EXISTS idx_v2_monitoring_alerts_type
ON v2_monitoring_alerts(alert_type);

CREATE INDEX IF NOT EXISTS idx_v2_monitoring_alerts_entity
ON v2_monitoring_alerts(entity_type, entity_id);

CREATE INDEX IF NOT EXISTS idx_v2_monitoring_alerts_component
ON v2_monitoring_alerts(component);

CREATE INDEX IF NOT EXISTS idx_v2_monitoring_alerts_status
ON v2_monitoring_alerts(status);

CREATE INDEX IF NOT EXISTS idx_v2_monitoring_alerts_severity
ON v2_monitoring_alerts(severity);

CREATE INDEX IF NOT EXISTS idx_v2_monitoring_alerts_cooldown
ON v2_monitoring_alerts(cooldown_until);

CREATE INDEX IF NOT EXISTS idx_v2_detection_health_component
ON v2_detection_health(component);

CREATE INDEX IF NOT EXISTS idx_v2_detection_health_status
ON v2_detection_health(status);

CREATE INDEX IF NOT EXISTS idx_v2_detection_health_checked
ON v2_detection_health(checked_at);

CREATE INDEX IF NOT EXISTS idx_v2_detection_health_last_success
ON v2_detection_health(last_successful_run);

-- Phase 3A V2 Stage 10 XDR-style correlation

CREATE TABLE IF NOT EXISTS v2_xdr_incidents (
    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    first_evidence_time TEXT NOT NULL,
    last_evidence_time TEXT NOT NULL,
    title TEXT NOT NULL,
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
    status TEXT NOT NULL DEFAULT 'New'
        CHECK (
            status IN (
                'New',
                'Investigating',
                'Confirmed',
                'Closed'
            )
        ),
    independent_source_count INTEGER NOT NULL
        CHECK (independent_source_count >= 2),
    evidence_count INTEGER NOT NULL
        CHECK (evidence_count >= 2),
    active_evidence_count INTEGER NOT NULL
        CHECK (active_evidence_count >= 1),
    exception_count INTEGER NOT NULL DEFAULT 0
        CHECK (exception_count >= 0),
    verified_activity_count INTEGER NOT NULL DEFAULT 0
        CHECK (verified_activity_count >= 0),
    usernames TEXT NOT NULL,
    service_accounts TEXT NOT NULL,
    device_ids TEXT NOT NULL,
    asset_ids TEXT NOT NULL,
    ip_addresses TEXT NOT NULL,
    mac_addresses TEXT NOT NULL,
    hostnames TEXT NOT NULL,
    process_names TEXT NOT NULL,
    file_hashes TEXT NOT NULL,
    locations TEXT NOT NULL,
    detection_types TEXT NOT NULL,
    attack_techniques TEXT NOT NULL,
    behaviours TEXT NOT NULL,
    correlation_reasons TEXT NOT NULL,
    vulnerability_context TEXT NOT NULL,
    evidence_keys TEXT NOT NULL,
    evidence TEXT NOT NULL,
    original_evidence_preserved INTEGER NOT NULL DEFAULT 1
        CHECK (original_evidence_preserved = 1)
);

CREATE TABLE IF NOT EXISTS v2_xdr_incident_evidence (
    evidence_link_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_link_key TEXT NOT NULL UNIQUE,
    incident_key TEXT NOT NULL,
    evidence_key TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_record_id TEXT NOT NULL,
    event_time TEXT NOT NULL,
    relationship TEXT NOT NULL
        CHECK (
            relationship IN (
                'shared_context',
                'explicit_finding_link',
                'vulnerability_context'
            )
        ),
    contribution_status TEXT NOT NULL
        CHECK (
            contribution_status IN (
                'active',
                'exception',
                'verified',
                'context_only'
            )
        ),
    shared_fields TEXT NOT NULL,
    source_event_ids TEXT NOT NULL,
    detection_type TEXT,
    severity TEXT NOT NULL,
    confidence INTEGER NOT NULL
        CHECK (confidence BETWEEN 0 AND 100),
    correlation_reasons TEXT NOT NULL,
    evidence TEXT NOT NULL,
    UNIQUE (incident_key, evidence_key)
);

CREATE TABLE IF NOT EXISTS v2_xdr_indicators (
    indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_key TEXT NOT NULL UNIQUE,
    incident_key TEXT NOT NULL,
    indicator_type TEXT NOT NULL
        CHECK (
            indicator_type IN (
                'ip_address',
                'file_hash',
                'hostname',
                'process_name',
                'mac_address'
            )
        ),
    indicator_value TEXT NOT NULL,
    classification TEXT NOT NULL
        CHECK (
            classification IN (
                'ioc',
                'supporting_observable'
            )
        ),
    confidence INTEGER NOT NULL
        CHECK (confidence BETWEEN 0 AND 100),
    source_evidence_keys TEXT NOT NULL,
    detection_types TEXT NOT NULL,
    evidence TEXT NOT NULL,
    UNIQUE (
        incident_key,
        indicator_type,
        indicator_value
    )
);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_incidents_first_time
ON v2_xdr_incidents(first_evidence_time);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_incidents_last_time
ON v2_xdr_incidents(last_evidence_time);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_incidents_severity
ON v2_xdr_incidents(severity);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_incidents_confidence
ON v2_xdr_incidents(confidence);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_incidents_status
ON v2_xdr_incidents(status);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_evidence_incident
ON v2_xdr_incident_evidence(incident_key);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_evidence_source
ON v2_xdr_incident_evidence(source_type);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_evidence_record
ON v2_xdr_incident_evidence(source_record_id);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_evidence_contribution
ON v2_xdr_incident_evidence(contribution_status);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_evidence_time
ON v2_xdr_incident_evidence(event_time);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_indicators_incident
ON v2_xdr_indicators(incident_key);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_indicators_type
ON v2_xdr_indicators(indicator_type);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_indicators_value
ON v2_xdr_indicators(indicator_value);

CREATE INDEX IF NOT EXISTS idx_v2_xdr_indicators_classification
ON v2_xdr_indicators(classification);
