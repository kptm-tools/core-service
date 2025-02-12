-- Migration: 000001_create_tenants_table.up.sql
CREATE TABLE IF NOT EXISTS tenants (
    id SERIAL PRIMARY KEY,
    provider_id UUID,
    application_id UUID,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
