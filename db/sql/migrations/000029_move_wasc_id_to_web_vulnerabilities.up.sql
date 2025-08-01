-- Migration: 000029_move_wasc_id_to_web_vulnerabilities.up.sql
-- Move wasc_id from vulnerabilities table to web_vulnerabilities table
-- to comply with class table inheritance pattern (ADR-003)

-- First, add wasc_id column to web_vulnerabilities table
ALTER TABLE web_vulnerabilities
    ADD COLUMN IF NOT EXISTS wasc_id VARCHAR(255);

-- Only copy data if wasc_id column exists in vulnerabilities table
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'vulnerabilities'
        AND column_name = 'wasc_id'
    ) THEN
        -- Copy existing wasc_id data from vulnerabilities to web_vulnerabilities
        UPDATE web_vulnerabilities wv
        SET wasc_id = v.wasc_id
        FROM vulnerabilities v
        WHERE wv.vulnerability_id = v.id
          AND v.wasc_id IS NOT NULL;
    END IF;
END $$;

-- Create index on wasc_id in web_vulnerabilities
CREATE INDEX IF NOT EXISTS idx_web_vulnerabilities_wasc_id ON web_vulnerabilities (wasc_id);

-- Drop the foreign key constraint from vulnerabilities table if it exists
ALTER TABLE vulnerabilities
    DROP CONSTRAINT IF EXISTS fk_vulnerabilities_wasc_details;

-- Drop the index on wasc_id in vulnerabilities table if it exists
DROP INDEX IF EXISTS idx_vulnerabilities_wasc_id;

-- Finally, drop the wasc_id column from vulnerabilities table if it exists
ALTER TABLE vulnerabilities
    DROP COLUMN IF EXISTS wasc_id;