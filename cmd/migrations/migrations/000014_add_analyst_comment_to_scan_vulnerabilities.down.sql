-- Migration: 000014_add_analyst_comment_to_scan_vulnerabilities.down.sql
ALTER TABLE scan_vulnerabilities
DROP COLUMN analyst_comment;
