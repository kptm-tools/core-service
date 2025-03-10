package services

import (
	"github.com/kptm-tools/core-service/pkg/domain"
	gomail "gopkg.in/mail.v2"
	"testing"

	"github.com/stretchr/testify/assert"
)

type MockSMTPClient struct {
	MockSendMail SendMailFunction
}

func (m *MockSMTPClient) SendMail(messages ...*gomail.Message) error {
	if m.MockSendMail != nil {
		return m.MockSendMail(messages...)
	}
	return nil
}

func TestSendEmail_Error_NoRecipients(t *testing.T) {
	mockSMTPClient := &MockSMTPClient{}

	emailService := &EmailService{
		Host:     "smtp.example.com",
		Port:     "587",
		Username: "your-email@example.com",
		Password: "your-email-password",
		SendMail: mockSMTPClient.SendMail,
	}

	err := emailService.SendEmail(nil, "Test Subject", "This is the email body.")
	assert.Error(t, err)
}

func TestSendEmail_Success(t *testing.T) {
	mockSMTPClient := &MockSMTPClient{}

	emailService := &EmailService{
		Host:     "smtp.example.com",
		Port:     "587",
		Username: "your-email@example.com",
		Password: "your-email-password",
		SendMail: mockSMTPClient.SendMail,
	}

	err := emailService.SendEmail([]*domain.Rapporteur{
		{
			"jose",
			"ada@gmail.com",
			false,
		},
	}, "Test Subject", "This is the email body.")
	assert.NoError(t, err)
}
