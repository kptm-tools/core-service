-- name: CreateOrUpdateCWEDetail :one 
INSERT INTO cwe_details (
    cwe_id,
    title,
    description,
    last_updated,
    owasp_top10_category
) VALUES (
  $1, $2, $3, $4, $5
) ON CONFLICT (cwe_id) DO UPDATE SET
  title = EXCLUDED.title,
  description = EXCLUDED.description,
  last_updated = EXCLUDED.last_updated,
  owasp_top10_category = EXCLUDED.owasp_top10_category
RETURNING *;

-- name: GetCWEDetailByCWEID :one
SELECT cwe_id, title, description, last_updated, created_at, owasp_top10_category
FROM cwe_details
WHERE cwe_id = $1;

-- name: GetCWEDetailWithMitigationsByID :many 
SELECT
  cd.cwe_id,
  cd.title,
  cd.description,
  cd.owasp_top10_category,
  cm.mitigation_id,
  cm.phase,
  cm.description AS mitigation_description,
  cm.effectiveness,
  cm.effectiveness_notes,
  cm.created_at AS mitigation_created_at
FROM cwe_details cd
LEFT JOIN cwe_mitigations cm ON cd.cwe_id = cm.cwe_id
WHERE cd.cwe_id = $1;
