-- Migration: 000026_create_vulnerabilities_table.up.sql
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id UUID NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    cve_id VARCHAR(255) REFERENCES cve_details (cve_id) ON DELETE RESTRICT,
    title VARCHAR(512) NOT NULL,
    description TEXT,
    severity VARCHAR(50) NOT NULL,
    vuln_source VARCHAR(100) NOT NULL, -- e.g., 'NVD', 'OWASP ZAP'
    vuln_type vulnerability_type_enum NOT NULL, -- e.g., 'NETWORK_OS', 'WEB_APPLICATION', 'CODE'
    analyst_comment TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Composite unique constraint to ensure unique findings per host/scan/cve
    -- This allows 'CVE-2023-12345' to appear multiple times, as long as (host_id, scan_id) changes.
    CONSTRAINT unique_vulnerability_finding UNIQUE (host_id, scan_id, cve_id)
);

-- Addd indexes for faster lookups
CREATE INDEX idx_vulnerabilities_host_id ON vulnerabilities (host_id);
CREATE INDEX idx_vulnerabilities_scan_id ON vulnerabilities (scan_id);
CREATE INDEX idx_vulnerabilities_cve_id ON vulnerabilities (cve_id);
CREATE INDEX idx_vulnerabilities_type ON vulnerabilities (vuln_type);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities (severity);
CREATE INDEX idx_vulnerabilities_created_at ON vulnerabilities (created_at DESC);
