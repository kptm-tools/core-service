package customerrors

import "errors"

var ErrEventBusUnhealthy = errors.New("event bus is unhealthy")
