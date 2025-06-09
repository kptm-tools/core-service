-- name: CreateHost :one
INSERT INTO hosts (
  tenant_id,
  operator_id,
  domain,
  ip,
  alias,
  rapporteurs
) VALUES (
  $1, $2, $3, $4, $5, $6
)
RETURNING *;

-- name: GetHostsByTenantID :many
SELECT *
FROM hosts
WHERE tenant_id = $1;

-- name: GetHostsByTenantIDAndHostsFilter :many
SELECT *
FROM hosts
WHERE tenant_id = $1 AND id = ANY(sqlc.arg(hosts_id_filter)::uuid[]);

-- name: GetHostByID :one
SELECT *
FROM hosts
WHERE id = $1;

-- name: PatchHostByID :one
UPDATE hosts
SET
  domain = COALESCE(sqlc.arg(domain), domain),
  ip = COALESCE(sqlc.arg(ip), ip),
  alias = COALESCE(sqlc.arg(alias), alias),
  rapporteurs = COALESCE(sqlc.arg(rapporteurs)::jsonb, rapporteurs)
WHERE id = $1
RETURNING *;

-- name: DeleteHostByID :execrows
DELETE FROM hosts
WHERE id = $1;

-- name: AliasExists :one 
SELECT EXISTS(SELECT 1 FROM hosts WHERE alias = $1);
