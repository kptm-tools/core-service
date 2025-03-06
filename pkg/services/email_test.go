package services

import (
	"net/smtp"
	"testing"

	"github.com/stretchr/testify/assert"
)

type MockSMTPClient struct {
	MockSendMail func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

func (m *MockSMTPClient) SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	if m.MockSendMail != nil {
		return m.MockSendMail(addr, a, from, to, msg)
	}
	return nil
}

func TestSendEmail(t *testing.T) {
	mockSMTPClient := &MockSMTPClient{}

	emailService := &EmailService{
		Host:     "smtp.example.com",
		Port:     "587",
		Username: "your-email@example.com",
		Password: "your-email-password",
		SendMail: mockSMTPClient.SendMail,
	}

	err := emailService.SendEmail("recipient@example.com", "Test Subject", "This is the email body.")
	assert.NoError(t, err)
}
