package services

import (
	"errors"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	gomail "gopkg.in/mail.v2"
)

const (
	maxRetries        = 3
	initialRetryDelay = 5 * time.Second
)

type SendMailFunction func(...*gomail.Message) error

type EmailService struct {
	Host      string
	Port      string
	Username  string
	Password  string
	FromEmail string
	SendMail  SendMailFunction
}

var _ interfaces.IEmailService = (*EmailService)(nil)

func NewEmailService(host, port, username, password, fromEmail string) *EmailService {
	portNum, _ := strconv.ParseInt(port, 0, 0)
	dialer := gomail.Dialer{
		Host:           host,
		Port:           int(portNum),
		Username:       username,
		Password:       password,
		StartTLSPolicy: gomail.NoStartTLS,
	}

	return &EmailService{
		Host:      host,
		Port:      port,
		Username:  username,
		Password:  password,
		FromEmail: fromEmail,
		SendMail:  dialer.DialAndSend,
	}
}

func (s *EmailService) SendEmail(toAddress []*domain.Rapporteur, subject, body string) error {
	if len(toAddress) == 0 {
		return errors.New("no emails configured to be sent")
	}
	m := gomail.NewMessage()
	sizeAddress := len(toAddress)
	addresses := make([]string, sizeAddress)
	for i, recipient := range toAddress {
		addresses[i] = m.FormatAddress(recipient.Email, recipient.Name)
	}
	m.SetHeader("From", s.FromEmail)
	m.SetHeader("To", addresses...)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	if err := s.SendMail(m); err != nil {
		return err
	} else {
		slog.Info("Email sent")
	}
	return nil
}

func (s *EmailService) SendScanFailedEmail(recipient string, hostName string) error {
	subject := "Scan Failed of" + hostName
	body := "Dear Recipient, the scan has been failed"
	recipientRapporteur := []*domain.Rapporteur{
		{
			Name:        "",
			Email:       recipient,
			IsPrincipal: false,
		},
	}
	err := s.sendEmailWithRetry(recipientRapporteur, subject, body)
	if err != nil {
		return err
	}
	slog.Info("Email of Scan failed sent", slog.String("recipient", recipient))
	return nil
}

func (s *EmailService) SendScanCompletedEmail(recipient string, hostName string) error {
	subject := "Scan Completed of " + hostName
	body := "Dear Recipient, the scan has been completed"
	recipientRapporteur := []*domain.Rapporteur{
		{
			Name:        "",
			Email:       recipient,
			IsPrincipal: false,
		},
	}
	err := s.sendEmailWithRetry(recipientRapporteur, subject, body)
	if err != nil {
		return err
	}
	slog.Info("Email of Scan completed sent", slog.String("recipient", recipient))
	return nil
}

func (s *EmailService) SendScanCancelledEmail(recipient string, hostName string) error {
	subject := "Scan cancelled of " + hostName
	body := "Dear Recipient, the scan has been canceled"
	recipientRapporteur := []*domain.Rapporteur{
		{
			Name:        "",
			Email:       recipient,
			IsPrincipal: false,
		},
	}
	err := s.sendEmailWithRetry(recipientRapporteur, subject, body)
	if err != nil {
		return err
	}
	slog.Info("Email of Scan cancelled sent", slog.String("recipient", recipient))
	return nil
}

func calculateRetryDelay(attempt int) time.Duration {
	// Exponential backoff with jitter
	delay := initialRetryDelay * time.Duration(1<<uint(attempt))
	jitter := time.Duration(int64(float64(delay) * 0.2)) // +/- 20% jitter
	delay += jitter

	if delay > 15*time.Second {
		delay = 15 * time.Second
	}
	return delay
}

func shouldRetry(err error) bool {
	return os.IsTimeout(err)
}

func (s *EmailService) sendEmailWithRetry(toAddress []*domain.Rapporteur, subject, body string) error {
	var errSMTP error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		errSMTP = s.SendEmail(toAddress, subject, body)
		// Success case
		if errSMTP == nil {
			return nil
		}

		// Non-retriable error
		if !shouldRetry(errSMTP) {
			if errors.Is(errSMTP, customerrors.ErrGomailUncryptedConnection) || errors.Is(errSMTP, customerrors.ErrGomailWrongHostName) || errors.Is(errSMTP, customerrors.ErrGomailExpectedAuth) {
				return customerrors.ErrEmailAuth
			}
		}

		retryDelay := calculateRetryDelay(attempt)
		slog.Warn("Send Email service failed, retrying",
			slog.Int("attempt", attempt),
			slog.Duration("delay", retryDelay),
			slog.String("email", toAddress[0].Email))
		time.Sleep(retryDelay)
	}

	slog.Error("Send Email service failed after max retries",
		slog.Int("max_retries", maxRetries),
		slog.Any("error", errSMTP))
	return customerrors.ErrEmailTimeout
}
