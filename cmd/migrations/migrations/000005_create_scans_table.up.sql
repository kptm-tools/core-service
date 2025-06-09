-- Migration: 000005_create_scans_table.up.sql
CREATE TABLE IF NOT EXISTS scans (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id UUID NOT NULL,
      operator_id UUID NOT NULL,
      host_id UUID NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
      status scan_status NOT NULL DEFAULT 'Pending',
      started_at TIMESTAMP DEFAULT now(),
      ended_at TIMESTAMP DEFAULT NULL,
      created_at TIMESTAMP DEFAULT now(),
      updated_at TIMESTAMP DEFAULT now()
)
