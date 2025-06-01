-- Migration: 000003_create_credentials_table.up.sql
CREATE TABLE IF NOT EXISTS credentials (
    id SERIAL PRIMARY KEY,
    host_id UUID NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    password TEXT NOT NULL
)
