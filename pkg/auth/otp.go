package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// OTP is the data structure for a One-Time-Password. It is used to authenticate
// users to a WebSocket Hub.
type OTP struct {
	Key     string
	Created time.Time
}

// RetentionMap will contain the OTP key and the OTP as value.
// It must delete OTP's which are too old.
type RetentionMap map[string]OTP

// NewRetentionMap creates a RetentionMap and runs a goroutine to clean
// OTP's periodically.
func NewRetentionMap(ctx context.Context, retentionPeriod time.Duration) RetentionMap {
	rm := make(RetentionMap)

	go rm.Retention(ctx, retentionPeriod)

	return rm
}

func (rm RetentionMap) NewOTP() OTP {
	o := OTP{
		Key:     uuid.NewString(),
		Created: time.Now(),
	}

	rm[o.Key] = o
	return o
}

func (rm RetentionMap) VerifyOTP(otp string) bool {
	if _, ok := rm[otp]; !ok {
		return false
	}

	// delete(rm, otp) // Delete it because it's a ONE time password
	return true
}

// Retention is a go routine which periodically checks to see which OTP's are no longer valid.
func (rm RetentionMap) Retention(ctx context.Context, retentionPeriod time.Duration) {
	ticker := time.NewTicker(1000 * time.Millisecond)
	for {
		select {
		case <-ticker.C:
			for key, otp := range rm {
				if time.Now().After(otp.Created.Add(retentionPeriod)) {
					delete(rm, key)
				}
			}
		case <-ctx.Done():
			return
		}
	}
}
