-- Migration: 000020_add_scan_scheduling_trigger.down.sql
DROP TRIGGER IF EXISTS create_or_update_cron ON scan_scheduling;
DROP FUNCTION IF EXISTS register_cron();
