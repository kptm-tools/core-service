-- Migration: 000017_create_services_table.up.sql
ALTER TABLE scan_vulnerabilities
ADD COLUMN operating_system_id INTEGER REFERENCES operating_systems (id) ON DELETE CASCADE,
ADD COLUMN service_id INTEGER REFERENCES services (id) ON DELETE CASCADE,
ADD COLUMN description TEXT,
ADD COLUMN service_access VARCHAR(20),
ADD COLUMN complexity VARCHAR(20),
ADD COLUMN privileges_required VARCHAR(20),
ADD COLUMN likelihood VARCHAR(20),
ADD COLUMN risk_score NUMERIC(5, 2),
ADD COLUMN impact_score NUMERIC(5, 2),
ADD COLUMN exploit JSONB,
ADD COLUMN integrity_impact VARCHAR(20),
ADD COLUMN availability_impact VARCHAR(20),
ADD COLUMN base_severity VARCHAR(20),
ADD COLUMN published TIMESTAMP WITHOUT TIME ZONE,
ADD COLUMN last_updated TIMESTAMP WITHOUT TIME ZONE,
DROP COLUMN port,
DROP COLUMN protocol,
DROP COLUMN service_name,
DROP COLUMN service_version;

CREATE INDEX idx_scan_vulnerabilities_os_id ON scan_vulnerabilities (operating_system_id);
CREATE INDEX idx_scan_vulnerabilities_service_id ON scan_vulnerabilities (service_id);
