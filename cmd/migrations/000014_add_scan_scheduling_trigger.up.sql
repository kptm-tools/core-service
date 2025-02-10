-- Migration: 000014_add_scan_scheduling_trigger.up.sql
CREATE OR REPLACE FUNCTION register_cron()
RETURNS TRIGGER
LANGUAGE PLPGSQL
AS
$$
BEGIN
    SELECT cron.schedule(NEW.cron,'PERFORM pg_notify(''scan_cron'',
          json_build_object(
            ''scan_id'', NEW.scan_id,
            ''timestamp'', now(), ''period'', NEW.has_period
          )::text
        );');
    RETURN NEW;
END;
$$;

CREATE TRIGGER create_cron
AFTER INSERT ON scan_scheduling
FOR EACH ROW
EXECUTE FUNCTION register_cron();
