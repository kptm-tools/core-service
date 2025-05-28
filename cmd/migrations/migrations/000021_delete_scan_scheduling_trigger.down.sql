-- Migration: 000022_delete_scan_scheduling_trigger.down.sql
DROP TRIGGER IF EXISTS delete_scan_scheduling ON scan_scheduling;
DROP FUNCTION IF EXISTS when_delete_schedule();