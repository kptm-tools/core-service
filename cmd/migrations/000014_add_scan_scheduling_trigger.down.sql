-- Migration: 000014_add_scan_scheduling_trigger.down.sql
DROP TRIGGER IF EXISTS create_cron ON scan_scheduling;
DROP FUNCTION IF EXISTS register_cron();
