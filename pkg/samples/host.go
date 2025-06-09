package samples

import (
	"strings"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
)

func generateCredentials(size int) []domain.Credential {
	domainCredentials := make([]domain.Credential, size)
	for i := range size {
		domainCredentials[i] = domain.Credential{
			ID:       gofakeit.Int(),
			Username: gofakeit.Username(),
			Password: gofakeit.Password(true, true, true, true, false, 0),
		}
	}
	return domainCredentials
}

func generateRapporteurs(size int) []domain.Rapporteur {
	domainRapporteurs := make([]domain.Rapporteur, size)
	for i := range size {
		domainRapporteurs[i] = domain.Rapporteur{
			Name:        gofakeit.Name(),
			Email:       gofakeit.Email(),
			IsPrincipal: gofakeit.Bool(),
		}
	}
	return domainRapporteurs
}

func SampleHosts(size int, tenants []domain.Tenant) []domain.Host {
	gofakeit.Seed(0)
	domainHosts := make([]domain.Host, size)
	operators := make([]uuid.UUID, 2)
	operators[0] = uuid.MustParse("00000000-0000-0000-0000-111111111111")
	operators[1] = uuid.MustParse("00000000-0000-0000-0000-222222222222")
	for i := range size {
		domainName := gofakeit.DomainName()
		creationTime := gofakeit.DateRange(time.Now().AddDate(-100, 0, 0), time.Now().AddDate(-18, 0, 0)).UTC()
		indexTenant := gofakeit.Number(0, len(tenants)-1)
		domainHosts[i] = domain.Host{
			TenantID:    tenants[indexTenant].ID,
			OperatorID:  operators[indexTenant],
			Name:        strings.Split(domainName, ".")[0] + " " + gofakeit.AppVersion(),
			Domain:      "https://" + domainName,
			IP:          gofakeit.IPv4Address(),
			Credentials: generateCredentials(2),
			Rapporteurs: generateRapporteurs(3),
			CreatedAt:   creationTime,
			UpdatedAt:   creationTime,
		}
	}
	return domainHosts
}
