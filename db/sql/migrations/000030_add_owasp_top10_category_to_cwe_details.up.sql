-- Add owasp_top10_category column to cwe_details table
ALTER TABLE cwe_details
ADD COLUMN owasp_top10_category VARCHAR(255);