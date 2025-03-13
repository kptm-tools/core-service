-- Migration: 000024_add_vendor_comment_to_scan_vulnerabilities.up.sql
ALTER TABLE scan_vulnerabilities
ADD COLUMN vendor_comments JSONB NOT NULL DEFAULT '[]'::JSONB;
