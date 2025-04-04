package common

import (
	"errors"
)

var ErrMessageNotSupported = errors.New("this message type is not supported")

type IHandler interface {
	Handle(Message, IClient) error
}
