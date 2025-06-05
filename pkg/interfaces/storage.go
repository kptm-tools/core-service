package interfaces

import (
	"context"
)

type IStorage interface {
	Ping() error
}

// TxFunc is a function that takes a context with an active transaction
// and can perform database operations
type TxFunc func(ctx context.Context) error

// TxManager provides methods for executing functions within a database transaction.
type TxManager interface {
	DoInTX(ctx context.Context, fn TxFunc) error
}
