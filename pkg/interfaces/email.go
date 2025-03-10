package interfaces

import "github.com/kptm-tools/core-service/pkg/domain"

type IEmailService interface {
	SendEmail(to []*domain.Rapporteur, subject, body string) error
	SendScanFailedEmail(recipient, hostname string) error
	SendScanCompletedEmail(recipient, hostname string) error
	SendScanCancelledEmail(recipient, hostname string) error
}
