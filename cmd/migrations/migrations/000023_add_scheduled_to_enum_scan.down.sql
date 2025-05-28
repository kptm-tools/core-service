-- Migration: 000025_add_scheduled_to_enum.down.sql
DROP TYPE IF EXISTS scan_status;
CREATE TYPE scan_status AS ENUM ('Pending', 'InProgress', 'Completed', 'Failed', 'Cancelled');
