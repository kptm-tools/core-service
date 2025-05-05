package samples

import (
	"fmt"
	"github.com/brianvoe/gofakeit/v7"
	"github.com/kptm-tools/core-service/pkg/domain"
	"time"
)

type Credential struct {
	ID       int    `fake:"{number:1,100}"`
	HostID   string `fake:"name"`
	Username string `fake:"{name}"`
	Password string `fake:"{password}"`
}
type Rapporteur struct {
	Name        string `fake:"{name}"`
	Email       string `fake:"{email}"`
	IsPrincipal bool   `fake:"{boolean}"`
}

type Host struct {
	ID          int          `fake:"{number:1,100}"`
	TenantID    string       `fake:"{uuid}"`
	OperatorID  string       `fake:"{uuid}"`
	Name        string       `fake:"{name}"`
	Domain      string       `fake:"{DomainName}"`
	IP          string       `fake:"{IPv4Address}"`
	Credentials []Credential `fake:"{Rapporteur}"`
	Rapporteurs []Rapporteur `fake:"{Credential}"`
	CreatedAt   time.Time    `fake:"{time}"`
	UpdatedAt   time.Time    `fake:"{time}"`
}

func convertCredentials(credentials []Credential) []domain.Credential {
	domainCredentials := make([]domain.Credential, len(credentials))
	for i, cred := range credentials {
		domainCredentials[i] = domain.Credential{
			ID:       cred.ID,
			HostID:   cred.HostID,
			Username: cred.Username,
			Password: cred.Password,
		}
	}
	return domainCredentials
}

func convertRapporteurs(rapporteurs []Rapporteur) []domain.Rapporteur {
	domainRapporteurs := make([]domain.Rapporteur, len(rapporteurs))
	for i, rapporteur := range rapporteurs {
		domainRapporteurs[i] = domain.Rapporteur{
			Name:        rapporteur.Name,
			Email:       rapporteur.Email,
			IsPrincipal: rapporteur.IsPrincipal,
		}
	}
	return domainRapporteurs
}

func SampleHosts() []domain.Host {
	/*tenantID := "11111111-0000-0000-0000-000000000000"
	sampleOperatorID1 := "00000000-0000-0000-0000-111111111111"
	sampleOperatorID2 := "00000000-0000-0000-0000-222222222222"
	*/
	gofakeit.Seed(0)
	hosts := make([]Host, 10)

	gofakeit.Slice(&hosts)

	domainHosts := make([]domain.Host, len(hosts))
	for i, host := range hosts {
		fmt.Println(host)
		domainHosts[i] = domain.Host{
			ID:          host.ID,
			TenantID:    host.TenantID,
			OperatorID:  host.OperatorID,
			Name:        host.Name,
			Domain:      host.Domain,
			IP:          host.IP,
			Credentials: convertCredentials(host.Credentials),
			Rapporteurs: convertRapporteurs(host.Rapporteurs),
			CreatedAt:   host.CreatedAt,
			UpdatedAt:   host.UpdatedAt,
		}
	}

	return domainHosts
	/*[]domain.Host{
		{
			ID:         1,
			TenantID:   tenantID,
			OperatorID: sampleOperatorID1,
			Name:       "Web Server example.com", // More descriptive name
			Credential:     "example.com",            // Consistent with Scan Target
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
			Credential:      "anothersample.net",            // Consistent with Scan Target
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
			Credential:     "test-host.org",                 // Consistent with Scan Target
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
			Credential:      "subdomain.example.com",                  // Consistent with Scan Target
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
			Credential:      "printer.local",              // Using PTR record as Credential, or can keep "192.168.1.1" if PTR is not preferred
			IP:          "192.168.1.1",                // Consistent with Scan Target
			Credentials: []domain.Credential{},        // No credentials for printer in sample
			Rapporteurs: []domain.Rapporteur{},        // No rapporteurs needed for now
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		},
	}*/

}
