-- Migration: 000029_move_wasc_id_to_web_vulnerabilities.up.sql
-- Move wasc_id from vulnerabilities table to web_vulnerabilities table
-- to comply with class table inheritance pattern (ADR-003)

-- First, add wasc_id column to web_vulnerabilities table
ALTER TABLE web_vulnerabilities
    ADD COLUMN IF NOT EXISTS wasc_id VARCHAR(255);

-- Copy existing wasc_id data from vulnerabilities to web_vulnerabilities
UPDATE web_vulnerabilities wv
SET wasc_id = v.wasc_id
FROM vulnerabilities v
WHERE wv.vulnerability_id = v.id
  AND v.wasc_id IS NOT NULL;

-- Add foreign key constraint for wasc_id in web_vulnerabilities
ALTER TABLE web_vulnerabilities
    ADD CONSTRAINT fk_web_vulnerabilities_wasc_details
        FOREIGN KEY (wasc_id) REFERENCES wasc_details (wasc_id)
            ON DELETE SET NULL
            ON UPDATE CASCADE;

-- Create index on wasc_id in web_vulnerabilities
CREATE INDEX idx_web_vulnerabilities_wasc_id ON web_vulnerabilities (wasc_id);

-- Drop the foreign key constraint from vulnerabilities table
ALTER TABLE vulnerabilities
    DROP CONSTRAINT IF EXISTS fk_vulnerabilities_wasc_details;

-- Drop the index on wasc_id in vulnerabilities table
DROP INDEX IF EXISTS idx_vulnerabilities_wasc_id;

-- Finally, drop the wasc_id column from vulnerabilities table
ALTER TABLE vulnerabilities
    DROP COLUMN IF EXISTS wasc_id;