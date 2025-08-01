-- Migration: 000028_drop_table_wasc_details.down.sql
-- Only recreate the wasc_details table
-- The wasc_id column and its constraints are now handled by migration 25
CREATE TABLE IF NOT EXISTS wasc_details (
    wasc_id VARCHAR(255) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    last_updated TIMESTAMP WITH TIME ZONE NOT NULL
);