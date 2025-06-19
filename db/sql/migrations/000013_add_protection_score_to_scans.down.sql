-- Migration: 000011_add_protection_score_to_scans.down.sql
ALTER TABLE scans
DROP COLUMN protection_score;
