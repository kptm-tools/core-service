package services

import (
	"fmt"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"net/smtp"
)

type EmailService struct {
	Host     string
	Port     string
	Username string
	Password string
	SendMail func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

var _ interfaces.IEmailService = (*EmailService)(nil)

func NewEmailService(host, port, username, password string) *EmailService {
	return &EmailService{
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
		SendMail: smtp.SendMail,
	}
}

func (s *EmailService) SendEmail(to, subject, body string) error {
	auth := smtp.PlainAuth("", s.Username, s.Password, s.Host)

	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", to, subject, body))

	addr := fmt.Sprintf("%s:%s", s.Host, s.Port)

	err := s.SendMail(addr, auth, s.Username, []string{to}, msg)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}
