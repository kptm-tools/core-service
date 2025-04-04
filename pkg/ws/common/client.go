package common

import "github.com/kptm-tools/common/common/pkg/enums"

type IClient interface {
	GetID() string
	GetHub() IHub
	GetSend() chan []byte
	ReadMessages()
	WriteMessages()
	Close() error
}

type IReportClient interface {
	IClient // Embedded IClient interface. This means to implement IReportClient you must also implement IClient
	GetVectorStatus() map[enums.WeaknessType]float64
	SetVectorStatus(map[enums.WeaknessType]float64)
	UpdateVector(weaknessType enums.WeaknessType, value float64)
}
