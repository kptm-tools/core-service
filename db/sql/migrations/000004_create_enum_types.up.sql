-- Migration: 000004_create_enum_types.up.sql
-- CREATE ENUM TYPES
-- 000004_create_enum_types.up.sql
-- Tool enum
DO        $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type t
     JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE t.typname = 'tool_enum'
      AND n.nspname = 'public'
  ) THEN
    CREATE TYPE tool_enum AS ENUM ('DNSLookup', 'WhoIs', 'Harvester', 'Nmap');
  END IF;
END
$$;

-- Scan status enum
DO        $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type t
     JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE t.typname = 'scan_status'
      AND n.nspname = 'public'
  ) THEN
    CREATE TYPE scan_status AS ENUM (
      'Pending', 'InProgress', 'Completed', 'Failed', 'Cancelled', 'Scheduled'
    );
  END IF;
END
$$;

-- Port state enum
DO        $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type t
     JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE t.typname = 'port_state_enum'
      AND n.nspname = 'public'
  ) THEN
    CREATE TYPE port_state_enum AS ENUM ('open', 'closed', 'filtered');
  END IF;
END
$$;

-- Period enum
DO        $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type t
     JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE t.typname = 'period_enum'
      AND n.nspname = 'public'
  ) THEN
    CREATE TYPE period_enum AS ENUM ('Day', 'Week', 'Month', 'Year');
  END IF;
END
$$;

-- Vulnerability type enum
DO        $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type t
     JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE t.typname = 'vulnerability_type_enum'
      AND n.nspname = 'public'
  ) THEN
    CREATE TYPE vulnerability_type_enum AS ENUM (
      'NETWORK_OS', 'WEB_APPLICATION', 'CODE'
    );
  END IF;
END
$$;