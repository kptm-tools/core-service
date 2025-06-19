-- Migration: 000002_create_hosts_table.up.sql
CREATE TABLE IF NOT EXISTS hosts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    operator_id UUID NOT NULL,
    domain VARCHAR(2048),
    ip VARCHAR(15),
    alias VARCHAR(2048) UNIQUE NOT NULL,
    rapporteurs JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE EXTENSION IF NOT EXISTS pgcrypto;
