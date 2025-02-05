-- Migration: 000013_enable_cron.down.sql
DROP EXTENSION IF EXISTS pg_cron;
