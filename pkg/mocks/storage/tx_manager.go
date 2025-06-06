package mockstorage

import (
	"context"
	"fmt"

	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/testutil"
)

type MockTxManager struct {
	MockDoInTx func(context.Context, interfaces.TxFunc) error
}

var _ interfaces.TxManager = (*MockTxManager)(nil)

func (m *MockTxManager) DoInTX(ctx context.Context, fn interfaces.TxFunc) error {
	if m.MockDoInTx != nil {
		return m.MockDoInTx(ctx, fn)
	}
	panic(fmt.Sprintf("MockTxManager: method DoInTX called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}
