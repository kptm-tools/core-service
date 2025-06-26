-- name: CreateCWERemediation :one
INSERT INTO cwe_mitigations (
    cwe_id,
    mitigation_id,
    phase,
    description,
    effectiveness,
    effectiveness_notes,
    created_at
) VALUES (
  $1, $2, $3, $4, $5, $6, $7
)
ON CONFLICT (cwe_id, description, phase)
  DO UPDATE
    SET
      mitigation_id       = COALESCE(cwe_mitigations.mitigation_id, EXCLUDED.mitigation_id),
      effectiveness        = COALESCE(cwe_mitigations.effectiveness,  EXCLUDED.effectiveness),
      effectiveness_notes  = COALESCE(cwe_mitigations.effectiveness_notes, EXCLUDED.effectiveness_notes)
RETURNING *;


-- name: GetCWEDetailByID :one
SELECT
    id,
    cwe_id,
    mitigation_id,
    phase,
    description,
    effectiveness,
    effectiveness_notes,
    created_at
FROM cwe_mitigations
WHERE id = $1;

-- name: GetCWEDetailsByCWEID :many
SELECT
    id,
    cwe_id,
    mitigation_id,
    phase,
    description,
    effectiveness,
    effectiveness_notes,
    created_at
FROM cwe_mitigations
WHERE cwe_id = $1;