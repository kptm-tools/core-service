package events

import (
	"github.com/kptm-tools/common/common/enums"
	"slices"
)

func CanInsertScanResult(currentStatus string) bool {
	statusNotToUpdateResult := []string{enums.StatusFailed.String(), enums.StatusCancelled.String()}
	if !slices.Contains(statusNotToUpdateResult, currentStatus) {
		return true
	}
	return false
}
