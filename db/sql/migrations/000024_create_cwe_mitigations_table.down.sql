-- 000024_add_cwe_details_columns_and_create_cwe_mitigations.down.sql
-- Re-add the old mitigation columns to cwe_details (if they do not already exist)
ALTER     TABLE cwe_details
ADD       COLUMN IF NOT EXISTS mitigation_phase VARCHAR(255) NOT NULL,
ADD       COLUMN IF NOT EXISTS effectiveness VARCHAR(255) NOT NULL,
ADD       COLUMN IF NOT EXISTS effectiveness_notes TEXT NOT NULL;

-- Remove the newly added columns from cwe_details
ALTER     TABLE cwe_details
DROP      COLUMN IF EXISTS created_at;

-- Drop indexes on cwe_mitigations
DROP      INDEX IF EXISTS idx_cwe_mitigations_phase;

DROP      INDEX IF EXISTS idx_cwe_mitigations_mitigation_id;

DROP      INDEX IF EXISTS idx_cwe_mitigations_cwe_id;

-- Drop the foreign key constraint on cwe_mitigations (if it exists)
ALTER     TABLE cwe_mitigations
DROP      CONSTRAINT IF EXISTS fk_cwe_mitigations_cwe_details;

-- Drop the cwe_mitigations table
DROP      TABLE IF EXISTS cwe_mitigations;