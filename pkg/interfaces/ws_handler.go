package interfaces

import "github.com/kptm-tools/core-service/pkg/ws/common"

type IReportHandler interface {
	Handle(common.Message, IReportClient) error
}
