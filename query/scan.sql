-- name: GetScanByID :one
SELECT *
FROM scans
WHERE id = $1;

-- name: CreateScan :one
INSERT INTO scans (
  tenant_id,
  operator_id,
  host_id,
  status,
  started_at
) VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: ListScansForTenant :many
WITH aggregated_vulnerabilities AS (
SELECT
	s_cte.id AS scan_id,
	COUNT(v.id) AS total_vulnerabilities_count,
	SUM(CASE WHEN v.severity = 'Critical' THEN 1 ELSE 0 END) AS critical_count,
	SUM(CASE WHEN v.severity = 'High' THEN 1 ELSE 0 END) AS high_count,
	SUM(CASE WHEN v.severity = 'Medium' THEN 1 ELSE 0 END) AS medium_count,
	SUM(CASE WHEN v.severity = 'Low' THEN 1 ELSE 0 END) AS low_count,
	SUM(CASE WHEN v.severity = 'None' THEN 1 ELSE 0 END) AS none_count,
	SUM(CASE WHEN v.severity = 'Unknown' THEN 1 ELSE 0 END) AS unknown_count
FROM
	scans s_cte
LEFT JOIN
        vulnerabilities v ON
	s_cte.id = v.scan_id
WHERE
	-- Filter by tenant_id for aggregation
	s_cte.tenant_id = $1
GROUP BY
	s_cte.id
)
SELECT
	s.id AS scan_id,
	s.started_at AS scan_date,
	h.alias AS host_alias,
	CAST(
    EXTRACT(epoch FROM (COALESCE(s.ended_at, NOW()) - s.started_at))
    AS INTEGER
  ) AS duration_in_seconds,
	s.status,
	COALESCE(av.total_vulnerabilities_count, 0) AS total_vulnerabilities,
	COALESCE(av.critical_count, 0) AS critical_vulnerabilities,
	COALESCE(av.high_count, 0) AS high_vulnerabilities,
	COALESCE(av.medium_count, 0) AS medium_vulnerabilities,
	COALESCE(av.low_count, 0) AS low_vulnerabilities,
	COALESCE(av.none_count, 0) AS none_vulnerabilities,
	COALESCE(av.unknown_count, 0) AS unknown_vulnerabilities  
FROM
    scans s
INNER JOIN
    hosts h ON
	s.host_id = h.id
LEFT JOIN
    aggregated_vulnerabilities av ON
	s.id = av.scan_id
WHERE
	s.tenant_id = $1
	-- Filter out scans with a specific status (passed as parameter)
	AND s.status != 'Scheduled'
ORDER BY
	s.started_at DESC;

-- name: UpdateProtectionScoreForScan :exec
UPDATE scans
SET protection_score=$1, updated_at=now()
WHERE id=$2;

-- name: GetProtectionScoreForScan :one
WITH ScanVulnerabilityMaxCVSS AS (
    -- Step 1: For each vulnerability in the specified scan,
    -- find the highest CVSS score among its v2, v3.0, and v3.1 versions.
    SELECT
        GREATEST(
            COALESCE(cd.cvss_v31_base_score, 0.0), -- Treat NULL score as 0.0 for GREATEST
            COALESCE(cd.cvss_v30_base_score, 0.0),
            COALESCE(cd.cvss_v2_base_score, 0.0)
        ) AS highest_cvss_for_vulnerability
    FROM
        vulnerabilities v
    JOIN
        cve_details cd ON v.cve_id = cd.cve_id
    WHERE
        v.scan_id = $1 
        -- Only consider vulnerabilities that have at least one non-NULL CVSS score.
        AND (
            cd.cvss_v31_base_score IS NOT NULL OR
            cd.cvss_v30_base_score IS NOT NULL OR
            cd.cvss_v2_base_score IS NOT NULL
        )
)
-- Step 2: From all the highest_cvss_for_vulnerability values found for the scan,
-- pick the overall maximum. Then calculate the protection score.
SELECT

  CAST(
  1.0 - (COALESCE(MAX(svmc.highest_cvss_for_vulnerability), 0.0) / 10.0)
  AS DOUBLE PRECISION
  ) AS protection_score 
FROM
    ScanVulnerabilityMaxCVSS svmc;

-- name: GetScanInsights :one
    WITH severity_per_type AS (
SELECT
	cd.cwe AS vuln_type,
	MAX(
		GREATEST(
			cd.cvss_v31_base_score,
			cd.cvss_v30_base_score,
			cd.cvss_v2_base_score
		)
	) AS max_cvss
FROM
	vulnerabilities sv
LEFT JOIN
         cve_details cd ON
	sv.cve_id = cd.cve_id
WHERE
	sv.scan_id = $1
GROUP BY
	cd.cwe
  )
    SELECT
	s.id,
	h.alias AS scan_alias,
	s.started_at AS scan_date,
	COUNT(v.id) AS total_vulnerabilities,
	SUM(CASE WHEN v.severity = 'Unknown' THEN 1 ELSE 0 END) AS unknown_vulnerabilities,
	SUM(CASE WHEN v.severity = 'None' THEN 1 ELSE 0 END) AS none_vulnerabilities,
	SUM(CASE WHEN v.severity = 'Low' THEN 1 ELSE 0 END) AS low_vulnerabilities,
	SUM(CASE WHEN v.severity = 'Medium' THEN 1 ELSE 0 END) AS medium_vulnerabilities,
	SUM(CASE WHEN v.severity = 'High' THEN 1 ELSE 0 END) AS high_vulnerabilities,
	SUM(CASE WHEN v.severity = 'Critical' THEN 1 ELSE 0 END) AS critical_vulnerabilities,
	(
	SELECT
		json_object_agg(
          vuln_type,
          max_cvss
        )
	FROM
		severity_per_type
      ) AS severity_per_type_map
FROM
	scans s
INNER JOIN 
    	vulnerabilities v ON
	s.id = v.scan_id
INNER JOIN 
    	hosts h ON
	v.host_id = h.id
WHERE
	s.id = $1
GROUP BY
	s.id,
	h.alias,
	s.started_at;

-- name: GetPreviousScanOnHost :one
SELECT
	ps.*
FROM
	scans ps
JOIN scans cs ON
	ps.host_id = cs.host_id
WHERE
	cs.id = $1
	AND ps.created_at < cs.created_at
ORDER BY
	ps.created_at DESC
LIMIT 1;

-- name: UpdateScanStatus :exec
UPDATE scans
SET status = $1, updated_at = now()
WHERE id = $2;

-- name: UpdateScanStatusAndEndedAt :exec
UPDATE scans
SET status = $1, updated_at = now(), ended_at = $2
WHERE id = $3;

-- name: GetReportsByTenantID :many
SELECT
  s.id AS scan_id,
  h.domain AS host_name,
  h.ip AS ip,
  s.started_at as scan_date,
  (SELECT COUNT(sv.id) FROM vulnerabilities sv WHERE sv.scan_id = s.id) AS total_severities,
  CASE
    WHEN NOT EXISTS (
      SELECT 1
      FROM vulnerabilities sv
      WHERE sv.scan_id = s.id
        AND sv.analyst_comment IS NOT NULL
    ) THEN 'PENDING' -- CommentStatusPending: No commens on any vulnerability
    WHEN EXISTS (
      SELECT 1
      FROM vulnerabilities sv
      WHERE sv.scan_id = s.id
        AND sv.analyst_comment IS NOT NULL
        AND sv.severity = 'Critical'
    ) THEN 'CRITICAL' -- CommentStatusCritical: Comment on at least one Critical vulnerability
    ELSE 'NEW COMMENT' -- CommentStatusNewComment: At least one comment, but no Critical Severity Comments
  END AS comment_status
FROM scans s
INNER JOIN hosts h ON s.host_id = h.id
WHERE s.tenant_id = $1 AND s.status = 'Completed'
ORDER BY scan_date DESC;

-- name: GetScanDetailsForSummary :one
SELECT
  h.alias AS host_alias,
  s.host_id
FROM
  scans s
JOIN
  hosts h ON s.host_id = h.id
WHERE 
  s.id = $1;

-- name: GetLatestScanByHostID :one
SELECT *
FROM scans
WHERE
  host_id = $1
  AND started_at >= COALESCE($2, '1900-01-01'::timestamp)
  AND started_at <= COALESCE($3, NOW()::timestamp)
ORDER BY
  started_at DESC
LIMIT 1;

-- name: GetOldestScanByHostID :one
SELECT *
FROM scans
WHERE
  host_id = $1
  AND started_at >= COALESCE($2, '1900-01-01'::timestamp)
  AND started_at <= COALESCE($3, NOW()::timestamp)
ORDER BY
  started_at ASC
LIMIT 1;
