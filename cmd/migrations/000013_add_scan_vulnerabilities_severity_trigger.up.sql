-- Migration: 000013_add_scan_vulnerabilities_severity_trigger.up.sql
CREATE OR REPLACE FUNCTION calculate_scan_vulnerability_severity()
RETURNS TRIGGER AS $$
BEGIN
  NEW.severity := CASE
    WHEN NEW.cvss IS NULL THEN 'None'
    WHEN NEW.cvss < 4.0 THEN 'Low'
    WHEN NEW.cvss >= 4.0 AND NEW.cvss < 7.0 THEN 'Medium'
    WHEN NEW.cvss >= 7.0 AND NEW.cvss < 9.0 THEN 'High'
    WHEN NEW.cvss >= 9.0 THEN 'Critical'
    ELSE 'Unknown'
  END;
  RETURN NEW;
END;
$$ LANGUAGE PLPGSQL;

-- Trigger to execute the function on INSERT or UPDATE
CREATE TRIGGER add_scan_vulnerabilities_severity_trigger
BEFORE INSERT OR UPDATE ON scan_vulnerabilities
FOR EACH ROW
EXECUTE FUNCTION calculate_scan_vulnerability_severity();
