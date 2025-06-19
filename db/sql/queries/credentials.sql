-- name: CreateCredential :one
INSERT INTO credentials (
  host_id,
  username,
  password
) VALUES ($1, $2, $3)
RETURNING *;

-- name: GetCredentialsByHostID :many
SELECT *
FROM credentials
WHERE host_id = $1;

-- name: DeleteCredentialsByHostID :execrows
DELETE FROM credentials
WHERE host_id = $1;
