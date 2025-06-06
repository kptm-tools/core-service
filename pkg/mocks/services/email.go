package mockservices

import "github.com/kptm-tools/core-service/pkg/domain"

type MockEmailService struct {
	MockSendEmail              func(to []*domain.Rapporteur, subject, body string) error
	MockSendScanFailedEmail    func(recipient, hostname string) error
	MockSendScanCompletedEmail func(recipient, hostname string) error
	MockSendScanCancelledEmail func(recipient, hostname string) error
}

func (m *MockEmailService) SendEmail(to []*domain.Rapporteur, subject, body string) error {
	if m.MockSendEmail != nil {
		return m.MockSendEmail(to, subject, body)
	}
	return nil
}

func (m *MockEmailService) SendScanFailedEmail(recipient, hostname string) error {
	if m.MockSendScanFailedEmail != nil {
		return m.MockSendScanFailedEmail(recipient, hostname)
	}
	return nil
}

func (m *MockEmailService) SendScanCompletedEmail(recipient, hostname string) error {
	if m.MockSendScanCompletedEmail != nil {
		return m.MockSendScanCompletedEmail(recipient, hostname)
	}
	return nil
}

func (m *MockEmailService) SendScanCancelledEmail(recipient, hostname string) error {
	if m.MockSendScanCancelledEmail != nil {
		return m.MockSendScanCancelledEmail(recipient, hostname)
	}
	return nil
}
