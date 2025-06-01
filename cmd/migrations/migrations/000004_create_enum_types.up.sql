-- Migration: 000004_create_enum_types.up.sql
-- CREATE ENUM TYPES
CREATE TYPE tool_enum AS ENUM ('DNSLookup', 'WhoIs', 'Harvester', 'Nmap');
CREATE TYPE scan_status AS ENUM ('Pending', 'InProgress', 'Completed', 'Failed', 'Cancelled', 'Scheduled');
CREATE TYPE port_state_enum AS ENUM ('open', 'closed', 'filtered');
CREATE TYPE period_enum AS ENUM ('day', 'week', 'month','year');
CREATE TYPE vulnerability_type_enum AS ENUM ('NETWORK_OS', 'WEB_APPLICATION', 'CODE');
