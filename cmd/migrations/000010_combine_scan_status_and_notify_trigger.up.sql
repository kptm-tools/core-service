-- Migration: 000010_combine_scan_status_and_notify_trigger.up.sql
DROP TRIGGER IF EXISTS scan_update ON scan_results;
DROP FUNCTION IF EXISTS scan_status_changes();

CREATE OR REPLACE FUNCTION scan_status_and_notify()
RETURNS TRIGGER
LANGUAGE PLPGSQL
AS
$$
DECLARE
    quantityTools INT;
    quantityScanResults INT;
    currentStatus scan_status;
BEGIN
    -- Get the total number of tools
    SELECT COUNT(enumlabel) INTO quantityTools
    FROM pg_enum
    WHERE enumtypid = 'tool_enum'::regtype;
    
    -- Get the number of distinct scan results (tools) for this scan
    SELECT COUNT(DISTINCT tool) INTO quantityScanResults
    FROM scan_results
    WHERE scan_id = NEW.scan_id;
    
    -- Get current scan status
    SELECT status INTO currentStatus FROM scans WHERE id = NEW.scan_id;

    -- If scan is already completed, do nothing
    IF currentStatus = 'Completed' THEN
        RETURN NEW;
    END IF;

    -- Update status to 'InProgress' if at least one result exists and it's not yet 'InProgress'
    IF quantityScanResults > 0 AND currentStatus NOT IN ('InProgress', 'Completed') THEN
        UPDATE scans SET status = 'InProgress' WHERE id = NEW.scan_id;
    END IF;

    -- If all expected results are present, mark as 'Completed'
    IF quantityScanResults >= quantityTools THEN
        UPDATE scans SET status = 'Completed', ended_at = now() WHERE id = NEW.scan_id;
        PERFORM pg_notify('scan_completed',
          json_build_object(
            'scan_id', NEW.scan_id,
            'timestamp', now()
          )::text
        );
        END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER scan_status_and_notify_trigger
AFTER INSERT ON scan_results
FOR EACH ROW
EXECUTE FUNCTION scan_status_and_notify();
