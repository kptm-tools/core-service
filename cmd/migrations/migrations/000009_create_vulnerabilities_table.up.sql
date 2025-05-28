-- Migration: 000026_create_vulnerabilities_table.up.sql
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id UUID NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    cve_id VARCHAR(255) UNIQUE,
    title VARCHAR(512) NOT NULL,
    description TEXT,
    severity VARCHAR(50) NOT NULL,
    vuln_source VARCHAR(100) NOT NULL, -- e.g., 'NVD', 'OWASP ZAP'
    vuln_type VARCHAR(50) NOT NULL, -- e.g., 'NETWORK_OS', 'WEB_APPLICATION', 'CODE'
    analyst_comment TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add index for cve_id for faster lookups
CREATE INDEX idx_vulnerabilities_cve_id ON vulnerabilities (cve_id);
-- Add index for type for filtering
CREATE INDEX idx_vulnerabilities_type ON vulnerabilities (vuln_type);
-- Add index for severity filtering
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities (severity);
-- Add index for created_at for ordering
CREATE INDEX idx_vulnerabilities_created_at ON vulnerabilities
(created_at DESC);
