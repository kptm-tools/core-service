package samples

import (
	"time"

	"github.com/kptm-tools/core-service/pkg/domain"
)

func SampleHosts() []domain.Host {
	tenantID := "11111111-0000-0000-0000-000000000000"
	sampleOperatorID1 := "00000000-0000-0000-0000-111111111111"
	sampleOperatorID2 := "00000000-0000-0000-0000-222222222222"

	return []domain.Host{
		{
			ID:         1,
			TenantID:   tenantID,
			OperatorID: sampleOperatorID1,
			Name:       "Web Server",
			Domain:     "example.com",
			IP:         "93.184.216.34",
			Credentials: []domain.Credential{
				{
					ID:       1,
					HostID:   "example.com",
					Username: "admin",
					Password: "password123",
				},
			},
			Rapporteurs: []domain.Rapporteur{
				{
					Name:        "Alice Smith",
					Email:       "alice.smith@example.com",
					IsPrincipal: true,
				},
			},
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		},
		{
			ID:          2,
			TenantID:    tenantID,
			OperatorID:  sampleOperatorID1,
			Name:        "Mail Server",
			Domain:      "mail.anothersample.net",
			IP:          "203.0.113.45",
			Credentials: []domain.Credential{}, // No credentials for this host in sample
			Rapporteurs: []domain.Rapporteur{
				{
					Name:        "Bob Johnson",
					Email:       "bob.johnson@example.com",
					IsPrincipal: false,
				},
				{
					Name:        "Charlie Brown",
					Email:       "charlie.brown@example.com",
					IsPrincipal: true,
				},
			},
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		},
		{
			ID:         3,
			TenantID:   tenantID,
			OperatorID: sampleOperatorID2,
			Name:       "Internal Server",
			Domain:     "internal.test-host.org",
			IP:         "192.168.1.100",
			Credentials: []domain.Credential{
				{
					ID:       2,
					HostID:   "internal.test-host.org",
					Username: "user",
					Password: "securePass",
				},
				{
					ID:       3,
					HostID:   "internal.test-host.org",
					Username: "guest",
					Password: "guestPass",
				},
			},
			Rapporteurs: []domain.Rapporteur{
				{
					Name:        "David Davis",
					Email:       "david.davis@example.com",
					IsPrincipal: true,
				},
			},
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		},
	}
}
