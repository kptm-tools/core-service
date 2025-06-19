-- name: CreateOrUpdateCWEDetail :one 
INSERT INTO cwe_details (
    cwe_id,
    title,
    mitigation_phase,
    description,
    effectiveness,
    effectiveness_notes,
    last_updated
) VALUES (
  $1, $2, $3, $4, $5, $6, $7
)
ON CONFLICT (cwe_id) DO UPDATE SET
  title = EXCLUDED.title,
  mitigation_phase = EXCLUDED.mitigation_phase,
  description = EXCLUDED.description,
  effectiveness = EXCLUDED.effectiveness,
  effectiveness_notes = EXCLUDED.effectiveness_notes,
  last_updated = EXCLUDED.last_updated
RETURNING *;
