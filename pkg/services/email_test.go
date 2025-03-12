package services

import (
	"errors"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/stretchr/testify/assert"
	gomail "gopkg.in/mail.v2"
	"os"
	"testing"
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

func TestSendEmail_Error_RecipientEmpty(t *testing.T) {
	mockSMTPClient := &MockSMTPClient{}

	emailService := &EmailService{
		Host:     "smtp.example.com",
		Port:     "587",
		Username: "your-email@example.com",
		Password: "your-email-password",
		SendMail: mockSMTPClient.SendMail,
	}

	err := emailService.SendEmail(domain.Rapporteur{Email: ""}, "Test Subject", "This is the email body.")
	assert.Error(t, err)
}

func TestSendEmail_Error_RecipientNotEmail(t *testing.T) {
	mockSMTPClient := &MockSMTPClient{}

	emailService := &EmailService{
		Host:     "smtp.example.com",
		Port:     "587",
		Username: "your-email@example.com",
		Password: "your-email-password",
		SendMail: mockSMTPClient.SendMail,
	}

	err := emailService.SendEmail(domain.Rapporteur{Email: "aa.co"}, "Test Subject", "This is the email body.")
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

	err := emailService.SendEmail(domain.Rapporteur{
		Name:  "jose",
		Email: "ada@gmail.com",
	}, "Test Subject", "This is the email body.")
	assert.NoError(t, err)
}

func TestSendEmail_ErrorNotRetry(t *testing.T) {
	mockSMTPClient := &MockSMTPClient{
		MockSendMail: func(messages ...*gomail.Message) error {
			return errors.New("error with smtp")
		},
	}

	emailService := &EmailService{
		Host:     "",
		Port:     "587",
		Username: "your-email@example.com",
		Password: "",
		SendMail: mockSMTPClient.SendMail,
	}

	err := emailService.sendEmailWithRetry(domain.Rapporteur{Email: "aa@co"}, "Test Subject", "This is the email body.")
	assert.Error(t, err)
}

func TestSendEmail_ErrorNotRetryCustomError(t *testing.T) {
	mockSMTPClient := &MockSMTPClient{
		MockSendMail: func(messages ...*gomail.Message) error {
			return customerrors.ErrGomailWrongHostName
		},
	}

	emailService := &EmailService{
		Host:     "",
		Port:     "587",
		Username: "your-email@example.com",
		Password: "",
		SendMail: mockSMTPClient.SendMail,
	}

	err := emailService.sendEmailWithRetry(domain.Rapporteur{Email: "aa@co"}, "Test Subject", "This is the email body.")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, customerrors.ErrEmailAuth))
}

func TestSendEmail_RetryCustomError(t *testing.T) {
	mockSMTPClient := &MockSMTPClient{
		MockSendMail: func(messages ...*gomail.Message) error {
			return os.ErrDeadlineExceeded
		},
	}

	emailService := &EmailService{
		Host:     "",
		Port:     "587",
		Username: "your-email@example.com",
		Password: "",
		SendMail: mockSMTPClient.SendMail,
	}

	err := emailService.sendEmailWithRetry(domain.Rapporteur{Email: "aa@co"}, "Test Subject", "This is the email body.")
	assert.True(t, errors.Is(err, customerrors.ErrEmailTimeout))
}
