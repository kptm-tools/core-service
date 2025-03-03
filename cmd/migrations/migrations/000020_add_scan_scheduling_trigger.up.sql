-- Migration: 000020_add_scan_scheduling_trigger.up.sql
CREATE OR REPLACE FUNCTION launch_notification(
       hasPeriod varchar(5),
       scanScheduleID int
)
RETURNS INTEGER
LANGUAGE PLPGSQL
AS
$$
    DECLARE
        PHOST_ID int;
        PTENANT_ID UUID;
        POPERATOR_ID UUID;
        PSCAN_ID UUID;
        PPERIOD_NAME period_enum;
        PPERIOD_QUANTITY int;
        PLAST_DATE TIMESTAMP;
        PSCHEDULED_DATE TIMESTAMP;
        DIFFERENCE_SECONDS int;
        LIMIT_SECONDS int;
        DIFFERENCE_MINUTES int;
BEGIN
SELECT scan_id, period_name, period_quantity,last_run_date, scheduled_date FROM scan_scheduling WHERE id=scanScheduleID INTO PSCAN_ID, PPERIOD_NAME, PPERIOD_QUANTITY, PLAST_DATE, PSCHEDULED_DATE;
SELECT host_id,tenant_id, operator_id  FROM scans WHERE scans.id=PSCAN_ID INTO PHOST_ID, PTENANT_ID, POPERATOR_ID;
SELECT EXTRACT(EPOCH FROM AGE(NOW(), COALESCE(PLAST_DATE, NOW()))) INTO DIFFERENCE_SECONDS;
SELECT CASE WHEN PPERIOD_NAME ='day'::period_enum THEN PPERIOD_QUANTITY  * 24 * 60 * 60
            WHEN PPERIOD_NAME ='week'::period_enum THEN PPERIOD_QUANTITY * 7 * 24 * 60 * 60
            WHEN PPERIOD_NAME ='month'::period_enum THEN PPERIOD_QUANTITY * 30 * 24 * 60 * 60
            WHEN PPERIOD_NAME ='year'::period_enum THEN PPERIOD_QUANTITY * 365 * 24 * 60 * 60 + 24*60*60 ELSE 0 END INTO LIMIT_SECONDS;

SELECT EXTRACT(EPOCH FROM (NOW() - PSCHEDULED_DATE)) / 60 INTO DIFFERENCE_MINUTES;
RAISE NOTICE 'minutos %',DIFFERENCE_MINUTES;
IF DIFFERENCE_MINUTES>=-1 and (DIFFERENCE_SECONDS=0 OR DIFFERENCE_SECONDS >= LIMIT_SECONDS) THEN
    UPDATE scan_scheduling SET last_run_date=now(), scheduled_date=scheduled_date + make_interval(secs => LIMIT_SECONDS) WHERE id=scanScheduleID;
    PERFORM pg_notify('scan_cron',
          json_build_object(
            'scan_id', PSCAN_ID,
            'has_period', cast(hasPeriod as boolean),
            'host_id', PHOST_ID,
            'scan_schedule_id', scanScheduleID,
            'timestamp', now(),
            'tenant_id', PTENANT_ID,
            'operator_id', POPERATOR_ID,
            'next_schedule', to_char((PSCHEDULED_DATE + make_interval(secs => LIMIT_SECONDS)) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
          )::text
        );
ELSE
    RAISE NOTICE 'NOT ENTER IN NOTIFICATION';
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
    SELECT concat('select launch_notification(''',NEW.has_period,''',',NEW.id,')') INTO SCAN_LAUNCH;
    SELECT cron.schedule(CRON_EXP,SCAN_LAUNCH) INTO JOB_ID;
    UPDATE scan_scheduling SET cron_job_id=JOB_ID WHERE id= NEW.id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER create_or_update_cron
AFTER INSERT ON scan_scheduling
FOR EACH ROW
EXECUTE FUNCTION register_cron();
