CREATE TABLE IF NOT EXISTS network_os_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vulnerability_id UUID NOT NULL,
    scan_id UUID NOT NULL, -- The specific scan run that found this instance
    host_id UUID NOT NULL, -- The specific host this instance was found on
    operating_system_id INTEGER, -- The specific operating system this instance is related to
    service_id INTEGER, -- The specific service this instance is related to

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(vulnerability_id, scan_id, host_id,operating_system_id,service_id),
    CONSTRAINT fk_netos_vulns_vulnerability_id FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (id) ON DELETE CASCADE,
    CONSTRAINT fk_netos_vulns_scan_id FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE,
    CONSTRAINT fk_netos_vulns_host_id FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
    CONSTRAINT fk_netos_vulns_os_id FOREIGN KEY (operating_system_id) REFERENCES operating_systems (id) ON DELETE SET NULL, 
    CONSTRAINT fk_netos_vulns_service_id FOREIGN KEY (service_id) REFERENCES services (id) ON DELETE SET NULL
);
