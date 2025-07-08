package mockstorage

import (
	"context"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	repository "github.com/kptm-tools/core-service/db"
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
	return nil, nil
}
