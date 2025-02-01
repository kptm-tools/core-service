package interfaces

import "github.com/nats-io/nats.go"

type EventConsumer interface {
	HandleMessage(msg *nats.Msg)
}
