-- name: CreateScanSchedule :one
INSERT INTO scan_scheduling (
    scan_id,
    host_id,
    period_name,         -- This column should be NULLABLE in your DB schema
    period_quantity,     -- This column should be NULLABLE in your DB schema
    enabled,
    has_period,
    cron,
    scheduled_date
) VALUES (
    $1,
    $2,
    $3,  
    $4,
    $5, 
    $6,  
    $7, 
    $8
) RETURNING *;

-- name: GetScanSchedulebyID :one
SELECT *
FROM scan_scheduling
WHERE id = $1;

-- name: ListScanScheduleSummariesByTenant :many
SELECT
    ss.id AS id, -- Matches ScanScheduleSummary.ID (type will be int32 from SERIAL)
    ss.created_at AS created_date,
    h.alias AS host_alias,
    CASE
        WHEN ss.has_period = TRUE THEN CONCAT('Every ', ss.period_quantity, ' ', ss.period_name)
        ELSE 'Once'
    END AS frequency,
    ss.scheduled_date
FROM
    scan_scheduling ss
INNER JOIN
    scans s ON ss.scan_id = s.id
INNER JOIN
    hosts h ON s.host_id = h.id
WHERE
    s.tenant_id = $1 
ORDER BY
    ss.created_at DESC;


-- name: PatchScanScheduleByID :exec
UPDATE 
scan_scheduling 
SET period_name=$2, period_quantity=$3, has_period=$4, scheduled_date=$5, last_run_date=NULL, cron=$6, scan_id=$7, enabled=true, updated_at=$8 
WHERE id=$1;

-- name: DeleteScanSchedule :exec
DELETE
FROM scan_scheduling
WHERE id = $1;

-- name: DisableScanScheduleJob :exec
SELECT unregister_cron( $1, $2 );

-- name: EnableScanScheduleJob :exec
SELECT enable_cron_function( $1, $2, $3 );

-- name: UpdateScanScheduling :exec
UPDATE scan_scheduling
SET scan_id = $1, updated_at =now()
WHERE id = $2;
