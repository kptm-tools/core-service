-- name: GetScanByID :one
SELECT *
FROM scans
WHERE id = $1;

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
