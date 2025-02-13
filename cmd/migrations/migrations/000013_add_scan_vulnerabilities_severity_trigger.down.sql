-- Migration: 000013_add_scan_vulnerabilities_severity_trigger.down.sql
DROP TRIGGER IF EXISTS scan_vulnerabilities_severity_trigger ON scan_vulnerabilities;
DROP FUNCTION IF EXISTS calculate_scan_vulnerability_severity();
