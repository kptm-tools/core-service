package samples

import (
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/domain"
)

func SampleTenants() []domain.Tenant {
	c := config.LoadConfig()
	return []domain.Tenant{
		{
			ID:            uuid.New(),
			ProviderID:    c.FusionAuth.BlueprintTenantID,
			ApplicationID: c.FusionAuth.BlueprintApplicationID,
			CreatedAt:     time.Now().UTC(),
			UpdatedAt:     time.Now().UTC(),
		},
		{
			ID:            uuid.MustParse("11111111-0000-0000-0000-000000000000"),
			ProviderID:    "11111111-0000-0000-0000-000000000000",
			ApplicationID: "00000000-1111-0000-0000-000000000000",
			CreatedAt:     time.Now().UTC(),
			UpdatedAt:     time.Now().UTC(),
		},
	}
}
