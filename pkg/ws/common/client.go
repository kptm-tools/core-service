package common

type IClient interface {
	GetID() string
	GetHub() IHub
	GetSend() chan []byte
	ReadMessages()
	WriteMessages()
	Close() error
}
