-- Migration: 000004_create_enum_types.up.sql
-- CREATE ENUM TYPES
-- 000004_create_enum_types.up.sql
-- Tool enum
CREATE TYPE tool_enum AS ENUM ('DNSLookup', 'WhoIs', 'Harvester', 'Nmap','WebScan');
CREATE TYPE scan_status AS ENUM ('Pending', 'InProgress', 'Completed', 'Failed', 'Cancelled', 'Scheduled');
CREATE TYPE port_state_enum AS ENUM ('open', 'closed', 'filtered');
CREATE TYPE period_enum AS ENUM ('Day', 'Week', 'Month','Year');
CREATE TYPE vulnerability_type_enum AS ENUM ('NETWORK_OS', 'WEB_APPLICATION', 'CODE');