-- Migration: 000009_add_scan_status_trigger.down.sql
DROP TRIGGER IF EXISTS scan_update ON scan_results;
DROP FUNCTION IF EXISTS scan_status_changes();
