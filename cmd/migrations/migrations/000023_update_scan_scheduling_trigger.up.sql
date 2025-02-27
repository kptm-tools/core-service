-- Migration: 000023_update_scan_scheduling_trigger.up.sql
CREATE OR REPLACE FUNCTION when_update_schedule()
RETURNS TRIGGER
LANGUAGE PLPGSQL
AS
$$
DECLARE
    CRON_EXP VARCHAR(20);
    SCAN_LAUNCH VARCHAR(250);
    JOB_ID BIGINT;
BEGIN
PERFORM cron.unschedule(OLD.cron_job_id);
DELETE FROM scans WHERE id=OLD.scan_id;
SELECT NEW.cron INTO CRON_EXP;
SELECT concat('select launch_notification(''',NEW.has_period,''',''',NEW.id,''')') INTO SCAN_LAUNCH;
SELECT cron.schedule(CRON_EXP,SCAN_LAUNCH) INTO JOB_ID;
UPDATE scan_scheduling SET cron_job_id=JOB_ID WHERE id= NEW.id;
RETURN NEW;
END;
$$;


-- Trigger to execute the function on INSERT or UPDATE
CREATE TRIGGER update_scan_scheduling
AFTER DELETE ON scan_scheduling
FOR EACH ROW
EXECUTE FUNCTION when_update_schedule();