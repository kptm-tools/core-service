-- Migration: 000001_create_tenants_table.up.sql
CREATE TABLE IF NOT EXISTS tenants(
    id integer NOT NULL,
    provider_id uuid,
    application_id uuid,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
