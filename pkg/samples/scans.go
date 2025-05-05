package samples

import (
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results"
	"github.com/kptm-tools/core-service/pkg/domain"
)

func SampleScans() []domain.Scan {
	tenantID := "11111111-0000-0000-0000-000000000000"
	sampleOperatorID1 := "00000000-0000-0000-0000-111111111111"
	currentYear := time.Now().Year()

	// Define months for the scans. More varied months across the year.
	month1 := time.Month(1)  // January
	month2 := time.Month(3)  // March
	month3 := time.Month(5)  // May
	month4 := time.Month(7)  // July
	month5 := time.Month(9)  // September
	month6 := time.Month(11) // November

	endedAt1 := time.Date(currentYear, month1, 28, 12, 30, 0, 0, time.UTC)
	endedAt2 := time.Date(currentYear, month2, 25, 18, 0, 0, 0, time.UTC)
	endedAt3 := time.Date(currentYear, month3, 20, 9, 15, 0, 0, time.UTC)
	endedAt4 := time.Date(currentYear, month4, 28, 14, 45, 0, 0, time.UTC)
	endedAt5 := time.Date(currentYear, month5, 15, 11, 0, 0, 0, time.UTC)
	endedAt6 := time.Date(currentYear, month6, 22, 16, 30, 0, 0, time.UTC)

	return []domain.Scan{
		{ // Scan 1: example.com - January
			ID:         uuid.New(),
			TenantID:   tenantID,
			OperatorID: sampleOperatorID1,
			HostID:     1,
			HostsStatus: []domain.StatusHost{
				{
					Host: "example.com",
					Metadata: []domain.Metadata{
						{Progress: "25%", Service: enums.EventSubjectName("nmap")},
						{Progress: "75%", Service: enums.EventSubjectName("whois")},
					},
				},
			},
			HostsResults: []domain.ResultHost{
				{Host: "example.com"},
			},
			Target: results.Target{
				Alias: "example dot com",
				Value: "example.com",
				Type:  enums.Domain,
			},
			CreatedAt: time.Date(currentYear, month1, 1, 10, 0, 0, 0, time.UTC),
			UpdatedAt: time.Date(currentYear, month1, 28, 12, 30, 0, 0, time.UTC),
			StartedAt: time.Date(currentYear, month1, 1, 10, 0, 0, 0, time.UTC),
			EndedAt:   &endedAt1,
			Status:    enums.StatusCompleted.String(),
		},
		{ // Scan 2: example.com - March (repeat scan, different month)
			ID:         uuid.New(),
			TenantID:   tenantID,
			OperatorID: sampleOperatorID1,
			HostID:     1,
			HostsResults: []domain.ResultHost{
				{Host: "example.com"},
			},
			Target: results.Target{
				Alias: "example dot com",
				Value: "example.com",
				Type:  enums.Domain,
			},
			CreatedAt: time.Date(currentYear, month2, 1, 10, 0, 0, 0, time.UTC), // Month 2 is March
			UpdatedAt: time.Date(currentYear, month2, 25, 18, 0, 0, 0, time.UTC),
			StartedAt: time.Date(currentYear, month2, 1, 10, 0, 0, 0, time.UTC),
			EndedAt:   &endedAt2,
			Status:    enums.StatusCompleted.String(),
		},
		{ // Scan 3: anothersample.net - May (new host)
			ID:         uuid.New(),
			TenantID:   tenantID,
			OperatorID: sampleOperatorID1,
			HostID:     2,
			HostsStatus: []domain.StatusHost{
				{
					Host: "anothersample.net",
					Metadata: []domain.Metadata{
						{Progress: "50%", Service: enums.EventSubjectName("dns_lookup")},
					},
				},
			},
			HostsResults: []domain.ResultHost{
				{Host: "anothersample.net"},
			},
			Target: results.Target{
				Alias: "anothersample",
				Value: "anothersample.net", // Corrected to top-level domain
				Type:  enums.Domain,        // Changed to Credential for top-level
			},
			CreatedAt: time.Date(currentYear, month3, 5, 14, 0, 0, 0, time.UTC), // Month 3 is May
			UpdatedAt: time.Date(currentYear, month3, 20, 9, 15, 0, 0, time.UTC),
			StartedAt: time.Date(currentYear, month3, 5, 14, 0, 0, 0, time.UTC),
			EndedAt:   &endedAt3,
			Status:    enums.StatusCompleted.String(),
		},
		{ // Scan 4: test-host.org - July (another new host)
			ID:         uuid.New(),
			TenantID:   tenantID,
			OperatorID: sampleOperatorID1,
			HostID:     3,
			HostsStatus: []domain.StatusHost{
				{
					Host: "test-host.org",
					Metadata: []domain.Metadata{
						{Progress: "90%", Service: enums.EventSubjectName("harvester")},
					},
				},
			},
			HostsResults: []domain.ResultHost{
				{Host: "test-host.org"},
			},
			Target: results.Target{
				Alias: "test-host",
				Value: "test-host.org",
				Type:  enums.Domain,
			},
			CreatedAt: time.Date(currentYear, month4, 10, 8, 0, 0, 0, time.UTC), // Month 4 is July
			UpdatedAt: time.Date(currentYear, month4, 28, 14, 45, 0, 0, time.UTC),
			StartedAt: time.Date(currentYear, month4, 10, 8, 0, 0, 0, time.UTC),
			EndedAt:   &endedAt4,
			Status:    enums.StatusCompleted.String(),
		},
		{ // Scan 5: subdomain.example.com - September (subdomain of example.com)
			ID:         uuid.New(),
			TenantID:   tenantID,
			OperatorID: sampleOperatorID1,
			HostID:     4,
			HostsStatus: []domain.StatusHost{
				{
					Host: "subdomain.example.com",
					Metadata: []domain.Metadata{
						{Progress: "60%", Service: enums.EventSubjectName("nmap")},
						{Progress: "80%", Service: enums.EventSubjectName("dns_lookup")},
					},
				},
			},
			HostsResults: []domain.ResultHost{
				{Host: "subdomain.example.com"},
			},
			Target: results.Target{
				Alias: "example subdomain",
				Value: "subdomain.example.com",
				Type:  enums.Subdomain, // Target is a subdomain
			},
			CreatedAt: time.Date(currentYear, month5, 2, 11, 30, 0, 0, time.UTC), // Month 5 is September
			UpdatedAt: time.Date(currentYear, month5, 15, 11, 0, 0, 0, time.UTC),
			StartedAt: time.Date(currentYear, month5, 2, 11, 30, 0, 0, time.UTC),
			EndedAt:   &endedAt5,
			Status:    enums.StatusCompleted.String(),
		},
		{ // Scan 6: 192.168.1.1 - November (IP address target)
			ID:         uuid.New(),
			TenantID:   tenantID,
			OperatorID: sampleOperatorID1,
			HostID:     5,
			HostsStatus: []domain.StatusHost{
				{
					Host: "192.168.1.1",
					Metadata: []domain.Metadata{
						{Progress: "40%", Service: enums.EventSubjectName("nmap")},
					},
				},
			},
			HostsResults: []domain.ResultHost{
				{Host: "192.168.1.1"},
			},
			Target: results.Target{
				Alias: "Private IP",
				Value: "192.168.1.1",
				Type:  enums.IP, // Target is an IP Address
			},
			CreatedAt: time.Date(currentYear, month6, 8, 9, 0, 0, 0, time.UTC), // Month 6 is November
			UpdatedAt: time.Date(currentYear, month6, 22, 16, 30, 0, 0, time.UTC),
			StartedAt: time.Date(currentYear, month6, 8, 9, 0, 0, 0, time.UTC),
			EndedAt:   &endedAt6,
			Status:    enums.StatusCompleted.String(),
		},
	}
}
