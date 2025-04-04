package common

import (
	"errors"
)

var ErrMessageNotSupported = errors.New("this message type is not supported")

type IReportHandler interface {
	Handle(Message, IReportClient) error
}
