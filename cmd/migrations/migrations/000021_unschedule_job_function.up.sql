-- Migration: 000021_unschedule_job_function.up.sql
CREATE OR REPLACE FUNCTION unregister_cron(
    scanScheduleID int
)
RETURNS INTEGER
LANGUAGE PLPGSQL
AS
$$
DECLARE
    JOB_ID BIGINT;
    RESULT_DATA INT;
BEGIN
    SELECT cron_job_id FROM scan_scheduling SC WHERE SC.id= scanScheduleID INTO JOB_ID;
    SELECT cron.unschedule(JOB_ID) :: int INTO RESULT_DATA;
    UPDATE scan_scheduling SET enabled=false where id=scanScheduleID;
    RETURN RESULT_DATA;
END;
$$;