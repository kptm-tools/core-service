-- Migration: 000017_add_scan_scheduling_trigger.up.sql
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
    DECLARE PSCAN_ID UUID;
    DECLARE PPERIOD_NAME period_enum;
    DECLARE PPERIOD_QUANTITY int;
    DECLARE PLAST_DATE int;
    DECLARE DIFFERENCE_SECONDS int;
    DECLARE LIMIT_SECONDS int;
BEGIN
SELECT scan_id, period_name, period_quantity,last_run_date FROM scan_scheduling WHERE id=scanScheduleID INTO PSCAN_ID, PPERIOD_NAME, PPERIOD_QUANTITY, PLAST_DATE;
SELECT host_id,tenant_id, operator_id  FROM scans WHERE scans.id=PSCAN_ID INTO PHOST_ID, PTENANT_ID, POPERATOR_ID;
SELECT EXTRACT(EPOCH FROM (PLAST_DATE-NOW())) INTO DIFFERENCE_SECONDS;
SELECT CASE WHEN PPERIOD_NAME ='DAY'::period_enum THEN PPERIOD_QUANTITY  * 24 * 60 * 60
            WHEN PPERIOD_NAME ='WEEK'::period_enum THEN PPERIOD_QUANTITY * 7 * 24 * 60 * 60
            WHEN PPERIOD_NAME ='MONTH'::period_enum THEN PPERIOD_QUANTITY * 30 * 24 * 60 * 60
            WHEN PPERIOD_NAME ='YEAR'::period_enum THEN PPERIOD_QUANTITY * 365 * 24 * 60 * 60 + 24*60*60 ELSE 0 END INTO LIMIT_SECONDS;
IF DIFFERENCE_SECONDS >= LIMIT_SECONDS THEN
    PERFORM pg_notify('scan_cron',
          json_build_object(
            'scan_id', PSCAN_ID,
            'has_period', cast(hasPeriod as boolean),
            'host_id', PHOST_ID,
            'scan_schedule_id', scanScheduleID,
            'timestamp', now(),
            'tenant_id', PTENANT_ID,
            'operator_id', POPERATOR_ID
          )::text
        );
END IF;
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
