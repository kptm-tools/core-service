package utils

import (
	"fmt"
	"math"
)

// SafeIntToInt32 safely converts an int to an int32.
// It returns an error if the int value is outside of a 32-bit integer.
func SafeIntToInt32(i int) (int32, error) {
	if i > math.MaxInt32 || i < math.MinInt32 {
		return 0, fmt.Errorf("value %d is out of int32 range", i)
	}
	return int32(i), nil
}
