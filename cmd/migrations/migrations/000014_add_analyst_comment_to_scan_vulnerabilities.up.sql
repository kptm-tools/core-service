-- Migration: 000014_add_analyst_comment_to_scan_vulnerabilities.up.sql
ALTER TABLE scan_vulnerabilities
ADD COLUMN analyst_comment TEXT NULL;
