-- Migration: 000025_wasc_in_vulnerabilities_table.up.sql
CREATE TABLE IF NOT EXISTS wasc_details (
    wasc_id VARCHAR(255) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    last_updated TIMESTAMP WITH TIME ZONE NOT NULL
                               );

ALTER TABLE vulnerabilities
    ADD COLUMN wasc_id VARCHAR(255);

ALTER TABLE vulnerabilities
    ADD CONSTRAINT fk_vulnerabilities_wasc_details
        FOREIGN KEY (wasc_id) REFERENCES wasc_details (wasc_id)
            ON DELETE SET NULL
            ON UPDATE CASCADE;

CREATE INDEX idx_vulnerabilities_wasc_id ON vulnerabilities (wasc_id);
