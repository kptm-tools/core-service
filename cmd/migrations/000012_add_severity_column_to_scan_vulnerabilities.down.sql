-- Migration: 000012_add_severity_column_to_scan_vulnerabilities.down.sql

DROP INDEX IF EXISTS idx_scan_vulnerabilities_severity;

ALTER TABLE scan_vulnerabilities DROP COLUMN severity;
