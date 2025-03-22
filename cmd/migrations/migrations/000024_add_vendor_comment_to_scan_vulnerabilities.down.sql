-- Migration: 000024_add_vendor_comment_to_scan_vulnerabilities.down.sql
ALTER TABLE scan_vulnerabilities
DROP COLUMN vendor_comments;
