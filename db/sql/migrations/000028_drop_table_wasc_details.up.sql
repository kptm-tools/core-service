-- Migration: 000028_drop_table_wasc_details.up.sql
-- Remove the foreign key constraint
ALTER TABLE vulnerabilities
    DROP CONSTRAINT IF EXISTS fk_vulnerabilities_wasc_details;

-- Drop the index on wasc_id
DROP INDEX IF EXISTS idx_vulnerabilities_wasc_id;
-- Drop the wasc_details table
DROP TABLE IF EXISTS wasc_details;

