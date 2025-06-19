-- Migration: 000027_create_vulnerabilities_table.up.sql
CREATE TABLE IF NOT EXISTS cve_details (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id VARCHAR(255) UNIQUE NOT NULL,
    cwe VARCHAR(255) NOT NULL,
    published_date TIMESTAMP WITH TIME ZONE,
    last_modified_date TIMESTAMP WITH TIME ZONE,

    -- CVSS v2 Metrics
    cvss_v2_vector VARCHAR(255),
    cvss_v2_base_score DECIMAL(3, 1),
    cvss_v2_base_severity VARCHAR(50), -- e.g., 'LOW', 'MEDIUM', 'HIGH'
    cvss_v2_exploitability_score DECIMAL(3, 1),
    cvss_v2_impact_score DECIMAL(3, 1),
    cvss_v2_access_vector VARCHAR(50),
    cvss_v2_access_complexity VARCHAR(50),
    cvss_v2_authentication VARCHAR(50),
    cvss_v2_confidentiality_impact VARCHAR(50),
    cvss_v2_integrity_impact VARCHAR(50),
    cvss_v2_availability_impact VARCHAR(50),

    -- CVSS v3.0 Metrics
    cvss_v30_vector VARCHAR(255),
    cvss_v30_base_score DECIMAL(3, 1),
    cvss_v30_base_severity VARCHAR(50), -- e.g., 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    cvss_v30_exploitability_score DECIMAL(3, 1),
    cvss_v30_impact_score DECIMAL(3, 1),
    cvss_v30_attack_vector VARCHAR(50),
    cvss_v30_attack_complexity VARCHAR(50),
    cvss_v30_privileges_required VARCHAR(50),
    cvss_v30_user_interaction VARCHAR(50),
    cvss_v30_scope VARCHAR(50),
    cvss_v30_confidentiality_impact VARCHAR(50),
    cvss_v30_integrity_impact VARCHAR(50),
    cvss_v30_availability_impact VARCHAR(50),

    -- CVSS v3.1 Metrics
    cvss_v31_vector VARCHAR(255),
    cvss_v31_base_score DECIMAL(3, 1),
    cvss_v31_base_severity VARCHAR(50), -- e.g., 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    cvss_v31_exploitability_score DECIMAL(3, 1),
    cvss_v31_exploit_code_maturity VARCHAR(50),
    cvss_v31_impact_score DECIMAL(3, 1),
    cvss_v31_attack_vector VARCHAR(50),
    cvss_v31_attack_complexity VARCHAR(50),
    cvss_v31_privileges_required VARCHAR(50),
    cvss_v31_user_interaction VARCHAR(50),
    cvss_v31_scope VARCHAR(50),
    cvss_v31_confidentiality_impact VARCHAR(50),
    cvss_v31_integrity_impact VARCHAR(50),
    cvss_v31_availability_impact VARCHAR(50),

    -- EPSS (Expected Exploitability Prediction System)
    epss_score DECIMAL(5, 4),
    epss_percentile DECIMAL(5, 2),

    -- Calculated metrics
    risk_score DECIMAL(5, 2),
    likelihood VARCHAR(50),

    -- Other NVD fields
    nvd_description TEXT, -- The main description from NVD
    nvd_references JSONB,
    vendor_comments JSONB,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_cve_details_cve_id ON cve_details (cve_id);
CREATE INDEX idx_cve_details_published ON cve_details (published_date);
