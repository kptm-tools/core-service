-- 000024_add_cwe_details_columns_and_create_cwe_mitigations.up.sql

-- Add new columns to cwe_details (if they do not already exist)
ALTER     TABLE cwe_details
ADD       COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;

-- Remove old mitigation columns from cwe_details (if they exist)
ALTER     TABLE cwe_details
DROP      COLUMN IF EXISTS mitigation_phase,
DROP      COLUMN IF EXISTS effectiveness,
DROP      COLUMN IF EXISTS effectiveness_notes;

-- Create the cwe_mitigations table (if it does not already exist)
CREATE    TABLE IF NOT EXISTS cwe_mitigations (
          id SERIAL PRIMARY KEY,
          cwe_id VARCHAR(255) NOT NULL,
          mitigation_id VARCHAR(255), -- Can be NULL for mitigations without a specific ID
          phase VARCHAR(255) NOT NULL, -- e.g., 'Implementation', 'Architecture and Design'
          description TEXT NOT NULL, -- Description of the mitigation
          effectiveness VARCHAR(255), -- Can be NULL
          effectiveness_notes TEXT, -- Can be NULL
          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
          );

ALTER TABLE cwe_mitigations
  ADD CONSTRAINT unique_cwe_mitigation_phase
  UNIQUE (cwe_id, description, phase);

-- -- Add foreign key constraint only if it does not already exist
-- ALTER TABLE cwe_mitigations
-- ADD CONSTRAINT fk_cwe_mitigation_cwe_id FOREIGN KEY (cwe_id) REFERENCES cwe_details (cwe_id);

CREATE    INDEX IF NOT EXISTS idx_cwe_mitigations_cwe_id ON cwe_mitigations (cwe_id);

CREATE    INDEX IF NOT EXISTS idx_cwe_mitigations_mitigation_id ON cwe_mitigations (mitigation_id);

CREATE    INDEX IF NOT EXISTS idx_cwe_mitigations_phase ON cwe_mitigations (phase);

