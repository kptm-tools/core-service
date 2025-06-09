-- Migration: 000018_create_scan_scheduling_table.up.sql
CREATE TABLE IF NOT EXISTS scan_scheduling (
    id SERIAL PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans (id),
    host_id UUID NOT NULL REFERENCES hosts (id),
    last_run_date TIMESTAMP,
    scheduled_date TIMESTAMP,
    period_name period_enum,
    period_quantity INT,
    enabled  BOOLEAN NOT NULL,
    has_period BOOLEAN NOT NULL,
    cron VARCHAR(20) NOT NULL,
    cron_job_id BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
