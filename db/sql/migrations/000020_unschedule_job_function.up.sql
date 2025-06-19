-- Migration: 000021_unschedule_job_function.up.sql
CREATE OR REPLACE FUNCTION unregister_cron(
    scanScheduleID int,
    withDelete BOOLEAN
)
RETURNS INTEGER
LANGUAGE PLPGSQL
AS
$$
DECLARE
    JOB_ID BIGINT;
    RESULT_DATA INT;
    PSCAN_ID UUID;
BEGIN
    SELECT cron_job_id, scan_id FROM scan_scheduling SC WHERE SC.id= scanScheduleID INTO JOB_ID, PSCAN_ID;
    SELECT cron.unschedule(JOB_ID) :: int INTO RESULT_DATA;
    UPDATE scan_scheduling SET enabled=false where id=scanScheduleID;
    IF withDelete THEN
        DELETE FROM scans where id=PSCAN_ID;
        UPDATE scan_scheduling SET scan_id=null where id=scanScheduleID;
    END IF;
    RETURN RESULT_DATA;
END;
$$;