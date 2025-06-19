-- name: CreateScanResult :exec
INSERT INTO scan_results (scan_id, tool, success, result)
VALUES ($1, $2, $3, $4);

