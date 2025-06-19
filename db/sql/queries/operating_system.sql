-- name: CreateOS :one
INSERT INTO operating_systems (
    host_id,
    scan_id,
    os_name,
    family,
    os_type,
    fingerprint,
    cpe,
    accuracy
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7,
    $8
)
RETURNING *;

-- name: GetOSByID :one
SELECT * FROM operating_systems
WHERE id = $1;
