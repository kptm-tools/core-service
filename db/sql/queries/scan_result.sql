-- name: CreateScanResult :exec
INSERT INTO scan_results (scan_id, tool, success, result)
VALUES ($1, $2, $3, $4);


-- name: GetScanResultsByScanID :many
SELECT * FROM scan_results where scan_id=$1 and tool = ANY($2::tool_enum[]);