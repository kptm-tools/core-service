-- Migration: 000003_create_credentials_table.up.sql
CREATE TABLE IF NOT EXISTS credentials(
      id SERIAL PRIMARY KEY,
      host_id integer REFERENCES hosts (id) ON DELETE CASCADE,
      username text  NOT NULL,
      password text  NOT NULL
)
