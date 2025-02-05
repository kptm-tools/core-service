-- Migration: 000012_create_scan_scheduling_table.up.sql
CREATE TABLE IF NOT EXISTS scan_scheduling (
                                            id SERIAL PRIMARY KEY,
                                            scan_id UUID NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    scheduled_at string NOT NULL,
    enabled  BOOLEAN NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
