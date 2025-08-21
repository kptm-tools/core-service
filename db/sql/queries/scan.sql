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
	SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_count,
	SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END) AS high_count,
	SUM(CASE WHEN v.severity = 'MEDIUM' THEN 1 ELSE 0 END) AS medium_count,
	SUM(CASE WHEN v.severity = 'LOW' THEN 1 ELSE 0 END) AS low_count,
	SUM(CASE WHEN v.severity = 'NONE' THEN 1 ELSE 0 END) AS none_count,
	SUM(CASE WHEN v.severity = 'UNKNOWN' THEN 1 ELSE 0 END) AS unknown_count
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
	cr.title AS vuln_type,
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
LEFT JOIN
  cwe_details cr ON
  sv.cwe_id = cr.cwe_id
WHERE
	sv.scan_id = $1
	AND cr.title IS NOT NULL  -- Filter out NULL titles to prevent json_object_agg errors
GROUP BY
	cr.title
  )
    SELECT
	s.id,
	h.alias AS scan_alias,
	s.started_at AS scan_date,
	COUNT(v.id) AS total_vulnerabilities,
	SUM(CASE WHEN v.severity = 'UNKNOWN' THEN 1 ELSE 0 END) AS unknown_vulnerabilities,
	SUM(CASE WHEN v.severity = 'NONE' THEN 1 ELSE 0 END) AS none_vulnerabilities,
	SUM(CASE WHEN v.severity = 'LOW' THEN 1 ELSE 0 END) AS low_vulnerabilities,
	SUM(CASE WHEN v.severity = 'MEDIUM' THEN 1 ELSE 0 END) AS medium_vulnerabilities,
	SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END) AS high_vulnerabilities,
	SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_vulnerabilities,
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

-- name: GetAssetsByScanID :many
WITH network_vuln_counts AS (
    -- Step 1: Count vulnerabilities linked via the network_os_vulnerabilities table (for OS and Services)
    SELECT
        nov.operating_system_id,
        nov.service_id,
        COUNT(v.id) AS total_vulnerabilities,
        SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
        SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END) AS high,
        SUM(CASE WHEN v.severity = 'MEDIUM' THEN 1 ELSE 0 END) AS medium,
        SUM(CASE WHEN v.severity = 'LOW' THEN 1 ELSE 0 END) AS low,
        SUM(CASE WHEN v.severity = 'NONE' THEN 1 ELSE 0 END) AS none,
        SUM(CASE WHEN v.severity = 'UNKNOWN' THEN 1 ELSE 0 END) AS unknown
    FROM
        vulnerabilities v
    JOIN
        network_os_vulnerabilities nov ON v.id = nov.vulnerability_id
    WHERE
        v.scan_id = $1
    GROUP BY
        nov.operating_system_id, nov.service_id
),
web_vuln_counts AS (
    -- Step 2: Count vulnerabilities linked via the web_vulnerabilities table (for Services only)
    SELECT
        wv.service_id,
        COUNT(v.id) AS total_vulnerabilities,
        SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
        SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END) AS high,
        SUM(CASE WHEN v.severity = 'MEDIUM' THEN 1 ELSE 0 END) AS medium,
        SUM(CASE WHEN v.severity = 'LOW' THEN 1 ELSE 0 END) AS low,
        SUM(CASE WHEN v.severity = 'NONE' THEN 1 ELSE 0 END) AS none,
        SUM(CASE WHEN v.severity = 'UNKNOWN' THEN 1 ELSE 0 END) AS unknown
    FROM
        vulnerabilities v
    JOIN
        web_vulnerabilities wv ON v.id = wv.vulnerability_id
    WHERE
        v.scan_id = $1
    GROUP BY
        wv.service_id
),
combined_service_counts AS (
    -- Step 3: Combine the counts for services, as they can have both network and web vulns.
    SELECT
        COALESCE(nvc.service_id, wvc.service_id) AS service_id,
        COALESCE(nvc.total_vulnerabilities, 0) + COALESCE(wvc.total_vulnerabilities, 0) AS total_vulnerabilities_count,
        COALESCE(nvc.critical, 0) + COALESCE(wvc.critical, 0) AS critical_count,
        COALESCE(nvc.high, 0) + COALESCE(wvc.high, 0) AS high_count,
        COALESCE(nvc.medium, 0) + COALESCE(wvc.medium, 0) AS medium_count,
        COALESCE(nvc.low, 0) + COALESCE(wvc.low, 0) AS low_count,
        COALESCE(nvc.none, 0) + COALESCE(wvc.none, 0) AS none_count,
        COALESCE(nvc.unknown, 0) + COALESCE(wvc.unknown, 0) AS unknown_count
    FROM
        network_vuln_counts nvc
    FULL OUTER JOIN
        web_vuln_counts wvc ON nvc.service_id = wvc.service_id
    WHERE
        nvc.service_id IS NOT NULL OR wvc.service_id IS NOT NULL
),
os_assets AS (
    -- Step 4: Get the OS asset and join ONLY with network vulnerability counts.
    SELECT
        'os' AS asset_type,
        os.id,
        os.host_id,
        os.scan_id,
        os.os_name AS name,
        NULL::VARCHAR AS version,
        os.family,
        os.os_type,
        NULL::INTEGER AS port,
        NULL::VARCHAR AS protocol,
        os.fingerprint,
        os.cpe,
        NULL::VARCHAR AS product,
        os.accuracy,
        NULL::port_state_enum AS port_state,
        COALESCE(nvc.total_vulnerabilities, 0) AS total_vulnerabilities_count,
        COALESCE(nvc.critical, 0) AS critical_count,
        COALESCE(nvc.high, 0) AS high_count,
        COALESCE(nvc.medium, 0) AS medium_count,
        COALESCE(nvc.low, 0) AS low_count,
        COALESCE(nvc.none, 0) AS none_count,
        COALESCE(nvc.unknown, 0) AS unknown_count,
        os.created_at,
        os.updated_at
    FROM
        operating_systems os
    LEFT JOIN
        network_vuln_counts nvc ON os.id = nvc.operating_system_id
    WHERE
        os.scan_id = $1
),
service_assets AS (
    -- Step 5: Get Service assets and join with the COMBINED vulnerability counts.
    SELECT
        'service' AS asset_type,
        s.id,
        s.host_id,
        s.scan_id,
        s.sv_name AS name,
        s.sv_version AS version,
        NULL::VARCHAR AS family,
        NULL::VARCHAR AS os_type,
        s.port,
        s.protocol,
        NULL::TEXT AS fingerprint,
        s.cpe,
        s.product,
        s.confidence AS accuracy,
        s.port_state,
        COALESCE(csc.total_vulnerabilities_count, 0) AS total_vulnerabilities_count,
        COALESCE(csc.critical_count, 0) AS critical_count,
        COALESCE(csc.high_count, 0) AS high_count,
        COALESCE(csc.medium_count, 0) AS medium_count,
        COALESCE(csc.low_count, 0) AS low_count,
        COALESCE(csc.none_count, 0) AS none_count,
        COALESCE(csc.unknown_count, 0) AS unknown_count,
        s.created_at,
        s.updated_at
    FROM
        services s
    LEFT JOIN
        combined_service_counts csc ON s.id = csc.service_id
    WHERE
        s.scan_id = $1
)
-- Step 6: Combine results.
SELECT * FROM os_assets
UNION ALL
SELECT * FROM service_assets
ORDER BY host_id, asset_type, created_at;

