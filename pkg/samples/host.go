package samples

import (
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/domain"
)

func SampleHosts() []domain.Host {
	c := config.LoadConfig()
	return []domain.Host{
		*domain.NewHost("https://www.aynitech.com", "", "11111111-0000-0000-0000-000000000000", "00000000-0000-0000-0000-111111111111", "aynitech-landing", []domain.Credential{}, []domain.Rapporteur{{Name: "Lucas", Email: "lucas@example.com", IsPrincipal: true}}),
		*domain.NewHost("https://www.i2linked.com", "", "11111111-0000-0000-0000-000000000000", "00000000-0000-0000-0000-111111111111", "i2linked", []domain.Credential{{Username: "myuser", Password: "mypassword"}, {Username: "myuser2", Password: "mypassword2"}}, []domain.Rapporteur{}),
		*domain.NewHost("https://www.example.com", "", c.BlueprintTenantID, "00000000-0000-0000-0000-222222222222", "example-website", []domain.Credential{}, []domain.Rapporteur{}),
	}
}
