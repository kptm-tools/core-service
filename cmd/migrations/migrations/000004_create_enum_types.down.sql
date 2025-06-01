-- Migration: 000004_create_enum_types.down.sql
-- Drop ENUM types 
DROP TYPE IF EXISTS port_state_enum;
DROP TYPE IF EXISTS scan_status;
DROP TYPE IF EXISTS tool_enum;
DROP TYPE IF EXISTS period_enum;
DROP TYPE IF EXISTS vulnerability_type_enum;
