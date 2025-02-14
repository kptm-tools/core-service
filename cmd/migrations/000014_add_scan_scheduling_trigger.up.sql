-- Migration: 000014_add_scan_scheduling_trigger.up.sql
CREATE OR REPLACE FUNCTION launch_notification(
       scanID UUID,
       hasPeriod varchar(5),
       scanScheduleID int
)
RETURNS INTEGER
LANGUAGE PLPGSQL
AS
$$
    DECLARE PHOST_ID int;
BEGIN
SELECT host_id FROM scans WHERE scans.id=scanID INTO PHOST_ID;
PERFORM pg_notify('scan_cron',
          json_build_object(
            'scan_id', scanID,
            'has_period', cast(hasPeriod as boolean),
            'host_id', PHOST_ID,
            'scan_schedule_id', scanScheduleID,
            'timestamp', now()
          )::text
        );
RETURN 1;
END;
$$;

CREATE OR REPLACE FUNCTION register_cron()
RETURNS TRIGGER
LANGUAGE PLPGSQL
AS
$$
DECLARE
    CRON_EXP VARCHAR(20);
    SCAN_LAUNCH VARCHAR(250);
    JOB_ID BIGINT;
BEGIN
    SELECT NEW.cron INTO CRON_EXP;
    SELECT concat('select launch_notification(''',NEW.scan_id,''',''',NEW.has_period,''',''',NEW.id,''')') INTO SCAN_LAUNCH;
    SELECT cron.schedule(CRON_EXP,SCAN_LAUNCH) INTO JOB_ID;
    UPDATE scan_scheduling SET cron_job_id=JOB_ID WHERE id= NEW.id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER create_cron
AFTER INSERT ON scan_scheduling
FOR EACH ROW
EXECUTE FUNCTION register_cron();
