-- Migration: 000026_create_web_vulnerabilities_table.up.sql
CREATE TABLE IF NOT EXISTS web_vulnerabilities (
    vulnerability_id UUID PRIMARY KEY,
    scan_id UUID NOT NULL, -- The specific scan run that found this instance
    host_id UUID NOT NULL, -- The specific host this instance was found on
    service_id INTEGER NOT NULL, -- The specific service this instance is related to
    solution_advice text,
    reference text,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_web_vulns_vulnerability_id FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (id) ON DELETE CASCADE,
    CONSTRAINT fk_web_vulns_scan_id FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE,
    CONSTRAINT fk_web_vulns_host_id FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
    CONSTRAINT fk_web_vulns_service_id FOREIGN KEY (service_id) REFERENCES services (id) ON DELETE SET NULL
);
