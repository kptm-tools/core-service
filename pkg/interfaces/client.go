package interfaces

import (
	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
)

type IClient interface {
	GetID() string
	GetSend() chan []byte
	ReadMessages()
	WriteMessages()
	Close() error
}

type IScanClient interface {
	IClient // Embedded IClient interface
	GetTenantID() uuid.UUID
}

type IReportClient interface {
	IClient // Embedded IClient interface. This means to implement IReportClient you must also implement IClient
	GetVectorStatus() map[enums.OwaspCategory]float64
	SetVectorStatus(map[enums.OwaspCategory]float64)
	UpdateVector(weaknessType enums.OwaspCategory, value float64)
	GetHubReport() IHubReport
	SetRoomID(string)
	GetRoomID() string
}
