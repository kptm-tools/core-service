-- Migration: 000022_delete_scan_scheduling_trigger.up.sql
CREATE OR REPLACE FUNCTION when_delete_schedule()
RETURNS TRIGGER
LANGUAGE PLPGSQL
AS
$$
BEGIN
PERFORM cron.unschedule(OLD.cron_job_id);
DELETE FROM scans where id=OLD.scan_id;
RETURN OLD;
END;
$$;


-- Trigger to execute the function on INSERT or UPDATE
CREATE TRIGGER delete_scan_scheduling
AFTER DELETE ON scan_scheduling
FOR EACH ROW
EXECUTE FUNCTION when_delete_schedule();