-- Migration: 000023_relocate_cwe_and_add_cwe_details_table.up.sql
CREATE TABLE IF NOT EXISTS cwe_details (
    cwe_id VARCHAR(255) PRIMARY KEY, -- e.g., 'CWE-79'
    title VARCHAR(255) NOT NULL, -- e.g., 'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)'
    mitigation_phase VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    effectiveness VARCHAR(255) NOT NULL,
    effectiveness_notes TEXT NOT NULL,
    last_updated TIMESTAMP WITH TIME ZONE NOT NULL
);

ALTER TABLE vulnerabilities
ADD COLUMN cwe_id VARCHAR(255);

ALTER TABLE vulnerabilities
ADD CONSTRAINT fk_vulnerabilities_cwe_details
FOREIGN KEY (cwe_id) REFERENCES cwe_details (cwe_id)
ON DELETE SET NULL
ON UPDATE CASCADE;

CREATE INDEX idx_vulnerabilities_cwe_id ON vulnerabilities (cwe_id);

ALTER TABLE cve_details
DROP COLUMN IF EXISTS cwe;
