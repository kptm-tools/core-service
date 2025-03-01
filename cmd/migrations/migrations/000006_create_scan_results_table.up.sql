-- Migration: 000006_create_scan_results_table.up.sql
CREATE TABLE IF NOT EXISTS scan_results (
    id SERIAL PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    tool tool_enum NOT NULL,
    success  BOOLEAN NOT NULL,
    result JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
