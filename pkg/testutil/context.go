package testutil

// contextKey is an unexported type to prevent key collisions across packages
type contextKey string

// TestNameKey is the context key for storing the name of a running test.
// It is used by mocks to provide moreinformative panic messages.
const TestNameKey = contextKey("test_name")
