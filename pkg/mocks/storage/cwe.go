package mockstorage

import (
	"context"
	"fmt"

	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/testutil"
)

type MockCWERepo struct {
	MockCreateOrUpdateCWE                     func(ctx context.Context, vuln tools.CWERemediation) (*tools.CWERemediation, error)
	MockCreateCWERemediation                  func(ctx context.Context, remediation *tools.CWERemediation) (*tools.CWERemediation, error)
	MockGetCWERemediationByID                 func(ctx context.Context, mitigationID string) (*tools.CWERemediation, error)
	MockGetCWERemediationsByCWEID             func(ctx context.Context, cweID string) ([]tools.CWERemediation, error)
	MockCreateOrUpdateCWEFromWebVulnerability func(ctx context.Context, vuln tools.WebVulnerability) (*tools.CWERemediation, error)
}

var _ interfaces.CWERepository = (*MockCWERepo)(nil)

func (m *MockCWERepo) CreateOrUpdateCWE(ctx context.Context, vuln tools.CWERemediation) (*tools.CWERemediation, error) {
	if m.MockCreateOrUpdateCWE != nil {
		return m.MockCreateOrUpdateCWE(ctx, vuln)
	}
	panic(fmt.Sprintf("MockCWERepo: method CreateOrUpdateCWE called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockCWERepo) CreateCWERemediation(ctx context.Context, remediation *tools.CWERemediation) (*tools.CWERemediation, error) {
	if m.MockCreateCWERemediation != nil {
		return m.MockCreateCWERemediation(ctx, remediation)
	}
	panic(fmt.Sprintf("MockCWERepo: method CreateCWERemediation called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockCWERepo) GetCWERemediationByID(ctx context.Context, mitigationID string) (*tools.CWERemediation, error) {
	if m.MockGetCWERemediationByID != nil {
		return m.MockGetCWERemediationByID(ctx, mitigationID)
	}
	panic(fmt.Sprintf("MockCWERepo: method GetCWERemediationByID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockCWERepo) GetCWERemediationsByCWEID(ctx context.Context, cweID string) ([]tools.CWERemediation, error) {
	if m.MockGetCWERemediationsByCWEID != nil {
		return m.MockGetCWERemediationsByCWEID(ctx, cweID)
	}
	panic(fmt.Sprintf("MockCWERepo: method GetCWERemediationsByCWEID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockCWERepo) CreateOrUpdateCWEFromWebVulnerability(ctx context.Context, vuln tools.WebVulnerability) (*tools.CWERemediation, error) {
	if m.MockCreateOrUpdateCWEFromWebVulnerability != nil {
		return m.MockCreateOrUpdateCWEFromWebVulnerability(ctx, vuln)
	}
	panic(fmt.Sprintf("MockCWERepo: method CreateOrUpdateCWEFromWebVulnerability called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))

}
