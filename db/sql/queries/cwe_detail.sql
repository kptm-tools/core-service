-- name: CreateOrUpdateCWEDetail :one 
INSERT INTO cwe_details (
    cwe_id,
    title,
    description,
    last_updated
) VALUES (
  $1, $2, $3, $4
) ON CONFLICT (cwe_id) DO UPDATE SET
  title = EXCLUDED.title,
  description = EXCLUDED.description,
  last_updated = EXCLUDED.last_updated
RETURNING *;

-- name: GetCWEDetailWithMitigationsByID :many 
SELECT
  cd.cwe_id,
  cd.title,
  cd.description,
  cm.id AS mitigation_id,
  cm.mitigation_id AS mitigation_code,
  cm.phase,
  cm.description AS mitigation_description,
  cm.effectiveness,
  cm.effectiveness_notes
FROM cwe_details cd
LEFT JOIN cwe_mitigations cm ON cd.cwe_id = cm.cwe_id
WHERE cd.cwe_id = $1;
