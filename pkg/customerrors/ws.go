package customerrors

import (
	"fmt"
)

// ServerSideError represents errors originating for the server's logic.
type ServerSideError struct {
	Reason string
}

func (e ServerSideError) Error() string {
	return fmt.Sprintf("server error: %s", e.Reason)
}

// MessageNotSupportedError specifically indicats that  the received message type is not supported.
type MessageNotSupportedError struct {
	MessageType string
}

func (e MessageNotSupportedError) Error() string {
	return fmt.Sprintf("message type not supported: %s", e.MessageType)
}

// ParseError represents errors that occur during the parsing of the incoming message.
type ParseError struct {
	Details string
	Err     error
}

func (e ParseError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("parsing error: %s - %v", e.Details, e.Err)
	}
	return fmt.Sprintf("parsing error: %s", e.Details)
}

// NewServerSideError creates a new ServerSideError
func NewServerSideError(reason string) error {
	return ServerSideError{Reason: reason}
}

// NewMessageNotSupportedError creates a new MessageNotSupportedError
func NewMessageNotSupportedError(messageType string) error {
	return MessageNotSupportedError{MessageType: messageType}
}

// NewParseError creates a new ParseError
func NewParseError(details string, err error) error {
	return ParseError{Details: details, Err: err}
}
