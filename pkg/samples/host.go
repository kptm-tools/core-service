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
			Name:       "Web Server example.com", // More descriptive name
			Domain:     "example.com",            // Consistent with Scan Target
			IP:         "192.0.2.1",              // Consistent with Scan Results (DNS Lookup A record - first IP)
			Credentials: []domain.Credential{
				{
					ID:       1,
					HostID:   "example.com", // HostID should be domain for consistency
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
			Name:        "Web Server anothersample.net", // More descriptive name
			Domain:      "anothersample.net",            // Consistent with Scan Target
			IP:          "203.0.113.10",                 // Consistent with Scan Results (DNS Lookup A record - first IP)
			Credentials: []domain.Credential{},          // No credentials for this host in sample
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
			Name:       "Embedded Server test-host.org", // More descriptive name
			Domain:     "test-host.org",                 // Consistent with Scan Target
			IP:         "10.0.0.5",                      // Consistent with Scan Results (DNS Lookup A record)
			Credentials: []domain.Credential{
				{
					ID:       2,
					HostID:   "test-host.org", // HostID should be domain for consistency
					Username: "user",
					Password: "securePass",
				},
				{
					ID:       3,
					HostID:   "test-host.org", // HostID should be domain for consistency
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
		{
			ID:          4,
			TenantID:    tenantID,
			OperatorID:  sampleOperatorID1,
			Name:        "Subdomain Server subdomain.example.com", // Descriptive name
			Domain:      "subdomain.example.com",                  // Consistent with Scan Target
			IP:          "192.0.2.50",                             // Consistent with Scan Results (DNS Lookup A record)
			Credentials: []domain.Credential{},                    // No credentials for subdomain in sample
			Rapporteurs: []domain.Rapporteur{},                    // No rapporteurs needed for now
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		},
		{
			ID:          5,
			TenantID:    tenantID,
			OperatorID:  sampleOperatorID1,
			Name:        "Printer Device 192.168.1.1", // Descriptive name for IP target
			Domain:      "printer.local",              // Using PTR record as Domain, or can keep "192.168.1.1" if PTR is not preferred
			IP:          "192.168.1.1",                // Consistent with Scan Target
			Credentials: []domain.Credential{},        // No credentials for printer in sample
			Rapporteurs: []domain.Rapporteur{},        // No rapporteurs needed for now
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		},
	}
}
