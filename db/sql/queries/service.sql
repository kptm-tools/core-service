-- name: CreateOrUpdateService :one
INSERT INTO services (
    host_id,
    scan_id,
    port,
    protocol,
    sv_name,
    sv_version,
    confidence,
    cpe,
    product,
    port_state
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7,
    $8,
    $9,
    $10
)
ON CONFLICT (scan_id, host_id, port, protocol) DO UPDATE SET
    scan_id = EXCLUDED.scan_id, -- Update scan_id if it's the latest scan
    sv_name = EXCLUDED.sv_name,
    sv_version = EXCLUDED.sv_version,
    confidence = EXCLUDED.confidence,
    cpe = EXCLUDED.cpe,
    product = EXCLUDED.product,
    port_state = EXCLUDED.port_state,
    updated_at = NOW()
RETURNING *;

-- name: GetServiceByID :one
SELECT *
FROM services
WHERE id = $1;

-- name: GetServiceByScanIDAndHostIDAndPortAndProtocol :one
SELECT *
FROM services
WHERE scan_id = $1
  AND host_id = $2
  AND port = $3
  AND protocol = $4;