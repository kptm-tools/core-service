package mocks

import (
	"context"
	"fmt"

	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/repository"
)

type MockCVERepo struct {
	MockCreateOrUpdateCVE func(ctx context.Context, vuln tools.Vulnerability) (*repository.CveDetail, error)
}

var _ interfaces.CVERepository = (*MockCVERepo)(nil)

func (m *MockCVERepo) CreateOrUpdateCVE(ctx context.Context, vuln tools.Vulnerability) (*repository.CveDetail, error) {
	if m.MockCreateOrUpdateCVE != nil {
		return m.MockCreateOrUpdateCVE(ctx, vuln)
	}
	panic(fmt.Sprintf("MockCVERepo: method CreateOrUpdateCVE called but not implemented for test: %s", ctx.Value("test_name")))
}
