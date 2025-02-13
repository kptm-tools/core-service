-- Migration: 000007_create_scan_vulnerabilities_table.up.sql
CREATE TABLE IF NOT EXISTS scan_vulnerabilities(
      id SERIAL PRIMARY KEY,
      vulnerability_id VARCHAR(100) NOT NULL,
      scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      host_id INT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
      tool tool_enum NOT NULL,
      type       VARCHAR(50) NOT NULL,
      cvss       DECIMAL(4,2),
      vuln_references  JSONB,
      exploitable BOOLEAN,
      port INT CHECK (port >= 0 AND port <= 65535),
      protocol VARCHAR(10),
      service_name VARCHAR(255),
      service_version VARCHAR(255),
      port_state port_state_enum NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
