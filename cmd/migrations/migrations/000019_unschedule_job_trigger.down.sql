-- Migration: 000019_unschedule_job_trigger.down.sql
DROP TRIGGER IF EXISTS unschedule_job_trigger ON scan_scheduling;