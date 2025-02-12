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

	// Define months for the scans. Ensure two are in the first semester and one in the second.
	month1 := time.Month(3)  // March (First Semester)
	month2 := time.Month(6)  // June (First Semester)
	month3 := time.Month(11) // November (Second Semester)

	endedAt1 := time.Date(currentYear, month1, 28, 12, 30, 0, 0, time.UTC)
	endedAt2 := time.Date(currentYear, month2, 25, 18, 0, 0, 0, time.UTC)
	endedAt3 := time.Date(currentYear, month3, 20, 9, 15, 0, 0, time.UTC)

	return []domain.Scan{
		{
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
		{
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
				Value: "subdomain.anothersample.net",
				Type:  enums.Subdomain,
			},
			CreatedAt: time.Date(currentYear, month2, 5, 14, 0, 0, 0, time.UTC),
			UpdatedAt: time.Date(currentYear, month2, 25, 18, 0, 0, 0, time.UTC),
			StartedAt: time.Date(currentYear, month2, 5, 14, 0, 0, 0, time.UTC),
			EndedAt:   &endedAt2,
			Status:    enums.StatusCompleted.String(),
		},
		{
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
			CreatedAt: time.Date(currentYear, month3, 10, 8, 0, 0, 0, time.UTC),
			UpdatedAt: time.Date(currentYear, month3, 20, 9, 15, 0, 0, time.UTC),
			StartedAt: time.Date(currentYear, month3, 10, 8, 0, 0, 0, time.UTC),
			EndedAt:   &endedAt3,
			Status:    enums.StatusCompleted.String(),
		},
	}
}
