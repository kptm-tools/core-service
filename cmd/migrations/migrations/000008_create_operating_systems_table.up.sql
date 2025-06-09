-- Migration: 000015_create_operating_systems_table.up.sql
CREATE TABLE IF NOT EXISTS operating_systems (
    id SERIAL PRIMARY KEY,
    host_id UUID NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    os_name VARCHAR(255),
    family VARCHAR(255),
    os_type VARCHAR(255),
    fingerprint TEXT,
    cpe VARCHAR(255),
    accuracy INTEGER,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_operating_systems_host_id ON operating_systems (host_id);
CREATE INDEX idx_operating_systems_scan_id ON operating_systems (scan_id);
