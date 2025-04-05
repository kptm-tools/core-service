package customerrors

import "errors"

var ErrMessageNotSupported = errors.New("this message type is not supported")
