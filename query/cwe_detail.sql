-- name: CreateOrUpdateCWEDetail :one 
INSERT INTO cwe_details (
  cwe_id,
  title,
  mitigation_phase,
  description,
  last_updated
) VALUES (
  $1, $2, $3, $4, $5
)
ON CONFLICT (cwe_id) DO UPDATE SET
  title = EXCLUDED.title,
  mitigation_phase = EXCLUDED.mitigation_phase,
  description = EXCLUDED.description,
  last_updated = EXCLUDED.last_updated
RETURNING *;
