-- name: GetScanByID :one
SELECT *
FROM scans
WHERE id = $1;
