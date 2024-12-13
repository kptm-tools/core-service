package samples

import (
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/domain"
)

func SampleTenants() []domain.Tenant {
	c := config.LoadConfig()
	return []domain.Tenant{
		*domain.NewTenant(c.BlueprintTenantID, c.BlueprintApplicationID),
		*domain.NewTenant("11111111-0000-0000-0000-000000000000", "00000000-1111-0000-0000-000000000000"),
	}
}
