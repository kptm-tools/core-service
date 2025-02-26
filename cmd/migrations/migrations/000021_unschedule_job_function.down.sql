-- Migration: 000021_unschedule_job_function.down.sql
DROP FUNCTION IF EXISTS unregister_cron;