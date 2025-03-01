-- Migration: 000008_create_indexes.up.sql
CREATE INDEX idx_scan_results_scan_id ON scan_results(scan_id);
CREATE INDEX idx_scan_vulnerabilities_scan_id ON scan_vulnerabilities(scan_id);
CREATE INDEX idx_scan_vulnerabilities_port ON scan_vulnerabilities(port);
