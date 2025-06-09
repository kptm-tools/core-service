-- Migration: 000023_relocate_cwe_and_add_cwe_details_table.up.sql
CREATE TABLE IF NOT EXISTS cwe_details (
  cwe_id VARCHAR(255) PRIMARY KEY, -- e.g., 'CWE-79'
  title VARCHAR(255), -- e.g., 'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)'
  mitigation_phase VARCHAR(255),
  description TEXT,
  last_updated TIMESTAMP WITH TIME ZONE
);

ALTER TABLE vulnerabilities
ADD COLUMN cwe VARCHAR(255);

ALTER TABLE vulnerabilities
ADD CONSTRAINT fk_vulnerabilities_cwe_details
FOREIGN KEY (cwe) REFERENCES cwe_details (cwe_id)
ON DELETE SET NULL;

ALTER TABLE cve_details
DROP COLUMN IF EXISTS cwe;

