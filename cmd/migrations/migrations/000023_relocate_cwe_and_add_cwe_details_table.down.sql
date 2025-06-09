-- Migration: 000023_relocate_cwe_and_add_cwe_details_table.down.sql
ALTER TABLE cve_details
ADD COLUMN cwe VARCHAR(255);

ALTER TABLE vulnerabilities
DROP CONSTRAINT IF EXISTS fk_vulnerabilities_cwe_details;

ALTER TABLE vulnerabilities
DROP COLUMN IF EXISTS cwe_id;

DROP TABLE IF EXISTS cwe_details;
