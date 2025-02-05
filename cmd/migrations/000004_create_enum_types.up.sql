-- Migration: 000004_create_enum_types.up.sql
-- CREATE ENUM TYPES
CREATE TYPE tool_enum AS ENUM ('DNSLookup', 'WhoIs', 'Harvester', 'Nmap');
CREATE TYPE scan_status AS ENUM ('Pending', 'InProgress', 'Completed', 'Failed', 'Cancelled');
CREATE TYPE port_state_enum AS ENUM ('open', 'closed', 'filtered');
