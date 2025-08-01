-- Migration: 000029_move_wasc_id_to_web_vulnerabilities.down.sql
-- Move wasc_id back from web_vulnerabilities table to vulnerabilities table

-- First, add wasc_id column back to vulnerabilities table
ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS wasc_id VARCHAR(255);

-- Copy wasc_id data from web_vulnerabilities back to vulnerabilities
UPDATE vulnerabilities v
SET wasc_id = wv.wasc_id
FROM web_vulnerabilities wv
WHERE v.id = wv.vulnerability_id
  AND wv.wasc_id IS NOT NULL;

-- Create index on wasc_id in vulnerabilities table
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_wasc_id ON vulnerabilities (wasc_id);

-- Drop the index on wasc_id in web_vulnerabilities table
DROP INDEX IF EXISTS idx_web_vulnerabilities_wasc_id;

-- Finally, drop the wasc_id column from web_vulnerabilities table
ALTER TABLE web_vulnerabilities
    DROP COLUMN IF EXISTS wasc_id;