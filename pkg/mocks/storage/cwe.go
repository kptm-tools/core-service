package mockstorage

import (
	"context"
	"fmt"

	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/repository"
	"github.com/kptm-tools/core-service/pkg/testutil"
)

type MockCWERepo struct {
	MockCreateOrUpdateCWE func(ctx context.Context, vuln tools.Vulnerability) (*repository.CweDetail, error)
}

var _ interfaces.CWERepository = (*MockCWERepo)(nil)

func (m *MockCWERepo) CreateOrUpdateCWE(ctx context.Context, vuln tools.Vulnerability) (*repository.CweDetail, error) {
	if m.MockCreateOrUpdateCWE != nil {
		return m.MockCreateOrUpdateCWE(ctx, vuln)
	}
	panic(fmt.Sprintf("MockCWERepo: method CreateOrUpdateCWE called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}
