-- name: CreateOrUpdateWASCDetail :one
INSERT INTO wasc_details (
    wasc_id,
    title,
    description,
    last_updated
) VALUES (
  $1, $2, $3, $4
) ON CONFLICT (wasc_id) DO UPDATE SET
  title = EXCLUDED.title,
  description = EXCLUDED.description,
  last_updated = EXCLUDED.last_updated
RETURNING *;
