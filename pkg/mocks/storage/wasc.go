package mockstorage

import (
	"context"
	"fmt"
	repository "github.com/kptm-tools/core-service/db"
	"github.com/kptm-tools/core-service/pkg/testutil"

	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type MockWASCRepo struct {
	MockCreateOrUpdateWASC func(ctx context.Context, webVulns tools.WebVulnerability) (*repository.WascDetail, error)
}

var _ interfaces.WASCRepository = (*MockWASCRepo)(nil)

func (m MockWASCRepo) CreateOrUpdateWASC(ctx context.Context, webVulns tools.WebVulnerability) (*repository.WascDetail, error) {
	if m.MockCreateOrUpdateWASC != nil {
		return m.MockCreateOrUpdateWASC(ctx, webVulns)
	}
	panic(fmt.Sprintf("MockWASCRepo CreateOrUpdateWASC called  but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}
