-- Migration: 000008_create_indexes.down.sql
DROP INDEX IF EXISTS idx_scan_results_scan_id;
DROP INDEX IF EXISTS idx_scan_vulnerabilities_scan_id;
DROP INDEX IF EXISTS idx_scan_vulnerabilities_port;
