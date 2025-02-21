-- Migration: 000017_create_services_table.down.sql
ALTER TABLE scan_vulnerabilities
DROP COLUMN operating_system_id,
DROP COLUMN service_id,
DROP COLUMN description,
DROP COLUMN access_type,
DROP COLUMN complexity,
DROP COLUMN privileges_required,
DROP COLUMN likelihood,
DROP COLUMN risk_score,
DROP COLUMN impact_score,
DROP COLUMN exploit_score,
DROP COLUMN exploitability,
DROP COLUMN integrity_impact,
DROP COLUMN availability_impact,
DROP COLUMN base_severity,
DROP COLUMN published,
DROP COLUMN last_updated,
ADD COLUMN port INTEGER CHECK (port >= 0 AND port <= 65535),
ADD COLUMN port_state port_state_enum NOT NULL,
ADD COLUMN protocol VARCHAR(10),
ADD COLUMN service_name VARCHAR(255),
ADD COLUMN service_version VARCHAR(255),
ADD COLUMN exploitable BOOL;

DROP INDEX idx_scan_vulnerabilities_os_id;
DROP INDEX idx_scan_vulnerabilities_service_id;
