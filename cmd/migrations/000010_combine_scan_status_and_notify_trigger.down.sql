-- Migration: 000010_combine_scan_status_and_notify_trigger.down.sql
DROP TRIGGER IF EXISTS scan_status_and_notify_trigger ON scan_results;
DROP FUNCTION IF EXISTS scan_status_and_notify();
