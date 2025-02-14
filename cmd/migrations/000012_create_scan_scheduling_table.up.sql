-- Migration: 000012_create_scan_scheduling_table.up.sql
CREATE TABLE IF NOT EXISTS scan_scheduling (
    id SERIAL PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    fixed_year INT NOT NULL,
    enabled  BOOLEAN NOT NULL,
    has_period BOOLEAN NOT NULL,
    cron VARCHAR(20) NOT NULL,
    cron_job_id BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
