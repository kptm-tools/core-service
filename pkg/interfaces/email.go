package interfaces

import "github.com/kptm-tools/core-service/pkg/domain"

type IEmailService interface {
	SendEmail(to *[]domain.Rapporteur, subject, body string) error
}
