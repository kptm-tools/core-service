-- Migration: 000025_add_scheduled_to_enum.up.sql
ALTER TYPE scan_status ADD VALUE 'Scheduled';
