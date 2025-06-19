-- Migration: 000016_create_services_table.up.sql
CREATE TABLE IF NOT EXISTS services (
    id SERIAL PRIMARY KEY,
    host_id UUID NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK (port >= 0 AND port <= 65535),
    protocol VARCHAR(10),
    sv_name VARCHAR(255),
    sv_version VARCHAR(255),
    confidence INTEGER,
    cpe VARCHAR(255),
    product VARCHAR(255),
    port_state port_state_enum NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (scan_id, host_id, port, protocol)
);

CREATE INDEX idx_services_host_id ON services (host_id);
CREATE INDEX idx_services_scan_id ON services (scan_id);
CREATE INDEX idx_services_port ON services (port);
