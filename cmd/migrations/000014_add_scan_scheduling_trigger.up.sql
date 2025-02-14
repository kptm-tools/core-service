-- Migration: 000014_add_scan_scheduling_trigger.up.sql
CREATE OR REPLACE FUNCTION launch_notification(
       hasPeriod varchar(5),
       scanScheduleID int
)
RETURNS INTEGER
LANGUAGE PLPGSQL
AS
$$
    DECLARE PHOST_ID int;
    DECLARE PTENANT_ID UUID;
    DECLARE POPERATOR_ID UUID;
    DECLARE SCAN_ID UUID;
BEGIN
SELECT scan_id FROM scan_scheduling WHERE id=scanScheduleID INTO SCAN_ID;
SELECT host_id,tenant_id, operator_id  FROM scans WHERE scans.id=SCAN_ID INTO PHOST_ID, PTENANT_ID, POPERATOR_ID;
PERFORM pg_notify('scan_cron',
          json_build_object(
            'scan_id', SCAN_ID,
            'has_period', cast(hasPeriod as boolean),
            'host_id', PHOST_ID,
            'scan_schedule_id', scanScheduleID,
            'timestamp', now(),
            'tenant_id', PTENANT_ID,
            'operator_id', POPERATOR_ID
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
    SELECT concat('select launch_notification(''',NEW.has_period,''',''',NEW.id,''')') INTO SCAN_LAUNCH;
    SELECT cron.schedule(CRON_EXP,SCAN_LAUNCH) INTO JOB_ID;
    UPDATE scan_scheduling SET cron_job_id=JOB_ID WHERE id= NEW.id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER create_cron
AFTER INSERT ON scan_scheduling
FOR EACH ROW
EXECUTE FUNCTION register_cron();
