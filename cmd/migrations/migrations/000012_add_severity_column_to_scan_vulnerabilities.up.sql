-- Migration: 000012_add_severity_column_to_scan_vulnerabilities.up.sql

ALTER TABLE scan_vulnerabilities ADD COLUMN severity VARCHAR(20);

UPDATE scan_vulnerabilities
SET severity =
  CASE
    WHEN cvss IS NULL THEN 'None'
    WHEN cvss < 4.0 THEN 'Low'
    WHEN cvss >= 4.0 AND cvss < 7.0 THEN 'Medium'
    WHEN cvss >= 7.0 AND cvss < 9.0 THEN 'High'
    WHEN cvss >= 9.0  THEN 'Critical'
    ELSE 'Unknown'
  END;

ALTER TABLE scan_vulnerabilities ALTER COLUMN severity SET NOT NULL;

CREATE INDEX idx_scan_vulnerabilities_severity ON scan_vulnerabilities(severity);
