package services

import (
	"errors"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	gomail "gopkg.in/mail.v2"
	"log/slog"
	"strconv"
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

func (s *EmailService) SendEmail(toAddress *[]domain.Rapporteur, subject, body string) error {
	if toAddress == nil || len(*toAddress) == 0 {
		return errors.New("no emails configured to be sent")
	}
	m := gomail.NewMessage()
	sizeAddress := len(*toAddress)
	addresses := make([]string, sizeAddress)
	for i, recipient := range *toAddress {
		addresses[i] = m.FormatAddress(recipient.Email, recipient.Name)
	}
	m.SetHeader("From", s.FromEmail)
	m.SetHeader("To", addresses...)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	if err := s.SendMail(m); err != nil {
		slog.Error(err.Error())
	} else {
		slog.Info("Email sent")
	}
	return nil
}
