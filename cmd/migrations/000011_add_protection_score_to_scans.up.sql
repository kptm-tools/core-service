-- Migration: 000011_add_protection_score_to_scans.up.sql
ALTER TABLE scans
ADD COLUMN protection_score DOUBLE PRECISION NOT NULL DEFAULT 0;
