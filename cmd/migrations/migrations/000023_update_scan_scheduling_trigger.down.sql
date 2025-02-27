-- Migration: 000023_update_scan_scheduling_trigger.down.sql
DROP TRIGGER IF EXISTS update_scan_scheduling ON scan_scheduling;
DROP FUNCTION IF EXISTS when_update_schedule();