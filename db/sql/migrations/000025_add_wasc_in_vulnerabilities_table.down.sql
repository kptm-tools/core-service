-- Migration: 000025_create_web_vulnerability_details_table.down.sql
ALTER TABLE vulnerabilities
DROP CONSTRAINT IF EXISTS fk_vulnerabilities_wasc_details;

ALTER TABLE vulnerabilities
DROP COLUMN IF EXISTS wasc_id;

DROP TABLE IF EXISTS wasc_details;