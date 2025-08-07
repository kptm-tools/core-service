-- Remove owasp_top10_category column from cwe_details table
ALTER TABLE cwe_details
DROP COLUMN owasp_top10_category;