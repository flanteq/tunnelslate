-- Initial release schema. Published migrations must remain unchanged;
-- subsequent schema changes belong in new numbered migration files.

-- Administrator accounts and panel sessions.

CREATE TABLE admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    password_setup_required INTEGER NOT NULL DEFAULT 0 CHECK (password_setup_required IN (0,1)),
    bootstrap_pending INTEGER NOT NULL DEFAULT 0 CHECK (bootstrap_pending IN (0,1))
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT 0,
    ip_address TEXT NOT NULL DEFAULT ''
);
CREATE INDEX sessions_admin ON sessions(admin_id);
CREATE INDEX sessions_expiry ON sessions(expires_at);

CREATE TABLE admin_totp (
    admin_id INTEGER PRIMARY KEY REFERENCES admins(id) ON DELETE CASCADE,
    secret TEXT NOT NULL,
    generation TEXT NOT NULL,
    last_used_step INTEGER NOT NULL DEFAULT -1
);

CREATE TABLE admin_totp_setups (
    admin_id INTEGER PRIMARY KEY REFERENCES admins(id) ON DELETE CASCADE,
    session_hash TEXT NOT NULL REFERENCES sessions(token_hash) ON DELETE CASCADE,
    setup_hash TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    secret TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX admin_totp_setups_expiry ON admin_totp_setups(expires_at);

CREATE TABLE admin_login_challenges (
    token_hash TEXT PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    generation TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX admin_login_challenges_admin ON admin_login_challenges(admin_id);
CREATE INDEX admin_login_challenges_expiry ON admin_login_challenges(expires_at);

CREATE TABLE admin_totp_attempts (
    admin_id INTEGER PRIMARY KEY REFERENCES admins(id) ON DELETE CASCADE,
    attempts INTEGER NOT NULL,
    reset_at INTEGER NOT NULL
);
CREATE INDEX admin_totp_attempts_expiry ON admin_totp_attempts(reset_at);

CREATE TABLE login_ip_failures (
    ip TEXT NOT NULL,
    failed_at INTEGER NOT NULL
);
CREATE INDEX login_ip_failures_address ON login_ip_failures(ip, failed_at);
CREATE INDEX login_ip_failures_expiry ON login_ip_failures(failed_at);

CREATE TABLE login_ip_bans (
    ip TEXT PRIMARY KEY,
    blocked_until INTEGER NOT NULL
);
CREATE INDEX login_ip_bans_expiry ON login_ip_bans(blocked_until);

-- VPN clients, devices and certificate operations.

CREATE TABLE clients (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0,1)),
    created_at INTEGER NOT NULL,
    deleted_at INTEGER
);
CREATE UNIQUE INDEX clients_name ON clients(name COLLATE NOCASE)
  WHERE deleted_at IS NULL;

CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(id),
    name TEXT NOT NULL,
    common_name TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    deleted_at INTEGER
);
CREATE UNIQUE INDEX devices_name ON devices(client_id,name COLLATE NOCASE)
  WHERE deleted_at IS NULL;

CREATE TABLE operations (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'running', 'succeeded', 'failed', 'partial')),
    step TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    device_id TEXT REFERENCES devices(id),
    actor TEXT NOT NULL DEFAULT '',
    request_key TEXT,
    request_hash TEXT NOT NULL DEFAULT '',
    arguments TEXT NOT NULL DEFAULT '{}',
    result_serial TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    client_id TEXT REFERENCES clients(id)
);
CREATE UNIQUE INDEX operations_active_client_delete ON operations(client_id)
  WHERE kind='delete_client' AND state IN ('pending','running','partial');
CREATE UNIQUE INDEX operations_active_client_revocation ON operations(client_id)
    WHERE kind='revoke_client' AND state IN ('pending','running','partial');
CREATE UNIQUE INDEX operations_active_device ON operations(device_id)
  WHERE state IN ('pending','running','partial');
CREATE UNIQUE INDEX operations_key ON operations(request_key);

CREATE TABLE certificates (
    serial TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    status TEXT NOT NULL CHECK (status IN ('valid', 'revoked', 'expired')),
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    revoked_at INTEGER,
    common_name TEXT,
    operation_id TEXT REFERENCES operations(id)
);
CREATE UNIQUE INDEX certificates_cn ON certificates(common_name);
CREATE INDEX certificates_latest_device ON certificates(device_id, not_before DESC, serial DESC);

-- Audit and server configuration.

CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    severity TEXT NOT NULL DEFAULT 'INFO'
    CHECK (severity IN ('INFO', 'WARNING', 'CRITICAL'))
);
CREATE INDEX audit_console_admin_events ON audit_events(id)
    WHERE actor='system:console' AND action IN ('admin.created','admin.password.reset','admin.totp.reset');
CREATE INDEX audit_events_created_at ON audit_events(created_at);

CREATE TABLE pki_bootstrap (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    state TEXT NOT NULL CHECK (state IN ('running','failed','ready')),
    step TEXT NOT NULL,
    actor TEXT NOT NULL,
    error TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL
);

CREATE TABLE vpn_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    configuration TEXT NOT NULL,
    revision INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE device_ccd (
    device_id TEXT PRIMARY KEY REFERENCES devices(id),
    configuration TEXT NOT NULL,
    static_ip TEXT NOT NULL DEFAULT '',
    revision INTEGER NOT NULL,
    published_revision INTEGER NOT NULL DEFAULT 0,
    published_vpn_revision INTEGER NOT NULL DEFAULT 0,
    publication_error TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX device_ccd_static_ip ON device_ccd(static_ip) WHERE static_ip != '';

CREATE TABLE device_ccd_retired_ips (
    ip TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    release_after INTEGER NOT NULL
);

-- Private client profile links.

CREATE TABLE client_links (
    client_id TEXT PRIMARY KEY REFERENCES clients(id),
    token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

CREATE TABLE client_link_sessions (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES client_links(client_id) ON DELETE CASCADE,
    link_hash TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX client_link_sessions_client ON client_link_sessions(client_id);
CREATE INDEX client_link_sessions_expiry ON client_link_sessions(expires_at);

-- External authentication belongs to the client and applies to all its devices.

CREATE TABLE vpn_auth_providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    kind TEXT NOT NULL CHECK(kind IN ('ldap','radius')),
    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
    configuration TEXT NOT NULL,
    encrypted_secret TEXT NOT NULL,
    revision INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE client_vpn_auth (
    client_id TEXT PRIMARY KEY REFERENCES clients(id),
    provider_id TEXT REFERENCES vpn_auth_providers(id),
    username TEXT NOT NULL DEFAULT '',
    revision INTEGER NOT NULL
);

CREATE TABLE vpn_auth_disconnects (
    common_name TEXT PRIMARY KEY
);

-- Independent lifetime totals and retained session/day history.

CREATE TABLE vpn_stat_totals (
    kind TEXT NOT NULL CHECK(kind IN ('server','client','device')),
    entity_id TEXT NOT NULL,
    sessions INTEGER NOT NULL DEFAULT 0,
    duration_seconds INTEGER NOT NULL DEFAULT 0,
    bytes_received INTEGER NOT NULL DEFAULT 0,
    bytes_sent INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(kind,entity_id)
);

CREATE TABLE vpn_stat_sessions (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    started_at INTEGER NOT NULL,
    observed_at INTEGER NOT NULL,
    ended_at INTEGER NOT NULL,
    state TEXT NOT NULL,
    duration_seconds INTEGER NOT NULL,
    bytes_received INTEGER NOT NULL,
    bytes_sent INTEGER NOT NULL
);
CREATE INDEX vpn_stat_sessions_device ON vpn_stat_sessions(device_id,started_at);
CREATE INDEX vpn_stat_sessions_expiry ON vpn_stat_sessions(ended_at) WHERE ended_at>0;

CREATE TABLE vpn_stat_days (
    device_id TEXT NOT NULL REFERENCES devices(id),
    date TEXT NOT NULL,
    sessions INTEGER NOT NULL DEFAULT 0,
    duration_seconds INTEGER NOT NULL DEFAULT 0,
    bytes_received INTEGER NOT NULL DEFAULT 0,
    bytes_sent INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(device_id,date)
);
CREATE INDEX vpn_stat_days_expiry ON vpn_stat_days(date);

CREATE TABLE vpn_stat_checkpoints (
    id TEXT PRIMARY KEY,
    ended_at INTEGER NOT NULL,
    record TEXT NOT NULL
);
CREATE INDEX vpn_stat_checkpoints_expiry ON vpn_stat_checkpoints(ended_at) WHERE ended_at>0;

CREATE TABLE vpn_stat_server_days (
    date TEXT PRIMARY KEY,
    bytes_received INTEGER NOT NULL DEFAULT 0,
    bytes_sent INTEGER NOT NULL DEFAULT 0
);

-- Panel customization and the optional metrics endpoint.

CREATE TABLE panel_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    instance_name TEXT NOT NULL DEFAULT '',
    metrics_enabled INTEGER NOT NULL DEFAULT 0,
    metrics_mtls INTEGER NOT NULL DEFAULT 0,
    metrics_source TEXT NOT NULL DEFAULT 'files',
    server_cert TEXT NOT NULL DEFAULT '',
    client_ca TEXT NOT NULL DEFAULT '',
    encrypted_key TEXT NOT NULL DEFAULT '',
    revision INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE monitoring_counters (
    scope TEXT PRIMARY KEY,
    value INTEGER NOT NULL DEFAULT 0
);

-- Initial singleton rows; VPN settings and the first administrator are
-- initialized by the application during startup.
INSERT INTO vpn_stat_totals(kind,entity_id) VALUES('server','');
INSERT INTO panel_settings(id) VALUES (1);
INSERT INTO monitoring_counters(scope) VALUES ('panel'), ('vpn');

CREATE TRIGGER monitoring_panel_failure AFTER INSERT ON login_ip_failures BEGIN
    UPDATE monitoring_counters SET value=value+1 WHERE scope='panel';
END;

CREATE TRIGGER monitoring_vpn_failure AFTER INSERT ON audit_events WHEN NEW.action='vpn.auth.reject' BEGIN
    UPDATE monitoring_counters SET value=value+1 WHERE scope='vpn';
END;

CREATE TRIGGER vpn_stat_delete_client AFTER UPDATE OF deleted_at ON clients
WHEN NEW.deleted_at IS NOT NULL AND OLD.deleted_at IS NULL
BEGIN
    DELETE FROM vpn_stat_sessions WHERE device_id IN (SELECT id FROM devices WHERE client_id=NEW.id);
    DELETE FROM vpn_stat_days WHERE device_id IN (SELECT id FROM devices WHERE client_id=NEW.id);
    DELETE FROM vpn_stat_totals WHERE kind='device' AND entity_id IN (SELECT id FROM devices WHERE client_id=NEW.id);
    DELETE FROM vpn_stat_totals WHERE kind='client' AND entity_id=NEW.id;
END;

CREATE TRIGGER vpn_stat_delete_device AFTER UPDATE OF deleted_at ON devices
WHEN NEW.deleted_at IS NOT NULL AND OLD.deleted_at IS NULL
BEGIN
    DELETE FROM vpn_stat_sessions WHERE device_id=NEW.id;
    DELETE FROM vpn_stat_days WHERE device_id=NEW.id;
    DELETE FROM vpn_stat_totals WHERE kind='device' AND entity_id=NEW.id;
END;
