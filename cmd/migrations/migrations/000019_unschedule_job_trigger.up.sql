-- Migration: 000019_unschedule_job_trigger.up.sql
CREATE OR REPLACE FUNCTION when_delete_schedule()
RETURNS TRIGGER
LANGUAGE PLPGSQL
AS
$$
BEGIN
PERFORM cron.unschedule(OLD.cron_job_id);
RETURN OLD;
END;
$$;


-- Trigger to execute the function on INSERT or UPDATE
CREATE TRIGGER unschedule_job_trigger
AFTER DELETE ON scan_scheduling
FOR EACH ROW
EXECUTE FUNCTION when_delete_schedule();