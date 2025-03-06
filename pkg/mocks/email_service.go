package mocks

import "github.com/kptm-tools/core-service/pkg/domain"

type MockEmailService struct {
	MockSendEmail func(to *[]domain.Rapporteur, subject, body string) error
}

func (m *MockEmailService) SendEmail(to *[]domain.Rapporteur, subject, body string) error {
	if m.MockSendEmail != nil {
		return m.MockSendEmail(to, subject, body)
	}
	return nil
}
