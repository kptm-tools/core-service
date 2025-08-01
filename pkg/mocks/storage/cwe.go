package mockstorage

import (
	"context"
	"fmt"
	"github.com/kptm-tools/core-service/pkg/domain"

	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/testutil"
)

type MockCWERepo struct {
	// Core methods for refactored approach
	MockGetCWEByID                      func(ctx context.Context, cweID string) (*domain.CWEDetail, error)
	MockCWEExists                       func(ctx context.Context, cweID string) (bool, error)
	MockCreateCWEStub                   func(ctx context.Context, cweID string) (*domain.CWEDetail, error)
	MockGetCWEDetailWithMitigationsByID func(ctx context.Context, cweID string) ([]domain.CWEDetailWithMitigations, error)

	// Legacy methods - kept for CWE pre-population script only
	MockCreateCWERemediation      func(ctx context.Context, remediation *tools.CWERemediation) (*tools.CWERemediation, error)
	MockGetCWERemediationByID     func(ctx context.Context, mitigationID string) (*tools.CWERemediation, error)
	MockGetCWERemediationsByCWEID func(ctx context.Context, cweID string) ([]tools.CWERemediation, error)
}

var _ interfaces.CWERepository = (*MockCWERepo)(nil)

// CreateOrUpdateCWE method removed - no longer needed with pre-populated CWE approach

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

// New methods for refactored approach

func (m *MockCWERepo) GetCWEByID(ctx context.Context, cweID string) (*domain.CWEDetail, error) {
	if m.MockGetCWEByID != nil {
		return m.MockGetCWEByID(ctx, cweID)
	}
	panic(fmt.Sprintf("MockCWERepo: method GetCWEByID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockCWERepo) CWEExists(ctx context.Context, cweID string) (bool, error) {
	if m.MockCWEExists != nil {
		return m.MockCWEExists(ctx, cweID)
	}
	panic(fmt.Sprintf("MockCWERepo: method CWEExists called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockCWERepo) CreateCWEStub(ctx context.Context, cweID string) (*domain.CWEDetail, error) {
	if m.MockCreateCWEStub != nil {
		return m.MockCreateCWEStub(ctx, cweID)
	}
	panic(fmt.Sprintf("MockCWERepo: method CreateCWEStub called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockCWERepo) GetCWEDetailWithMitigationsByID(ctx context.Context, cweID string) ([]domain.CWEDetailWithMitigations, error) {
	if m.MockGetCWEDetailWithMitigationsByID != nil {
		return m.MockGetCWEDetailWithMitigationsByID(ctx, cweID)
	}
	panic(fmt.Sprintf("MockCWERepo: method GetCWEDetailWithMitigationsByID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}
