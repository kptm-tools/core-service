package mockstorage

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	repository "github.com/kptm-tools/core-service/db"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/testutil"
)

type MockCVERepo struct {
	MockCreateOrUpdateCVE func(ctx context.Context, vuln tools.Vulnerability) (*repository.CveDetail, error)
	MockGetCVEDetailsByID func(ctx context.Context, cveID uuid.UUID) (*repository.CveDetail, error)
}

var _ interfaces.CVERepository = (*MockCVERepo)(nil)

func (m *MockCVERepo) CreateOrUpdateCVE(ctx context.Context, vuln tools.Vulnerability) (*repository.CveDetail, error) {
	if m.MockCreateOrUpdateCVE != nil {
		return m.MockCreateOrUpdateCVE(ctx, vuln)
	}
	panic(fmt.Sprintf("MockCVERepo: method CreateOrUpdateCVE called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockCVERepo) GetCVEDetailsByID(ctx context.Context, cveID uuid.UUID) (*repository.CveDetail, error) {
	if m.MockGetCVEDetailsByID != nil {
		return m.MockGetCVEDetailsByID(ctx, cveID)
	}
	panic(fmt.Sprintf("MockCVERepo: method MockGetCVEDetailsByID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}
