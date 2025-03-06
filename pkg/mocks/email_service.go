package mocks

type MockEmailService struct {
	MockSendEmail func(to, subject, body string) error
}

func (m *MockEmailService) SendEmail(to, subject, body string) error {
	if m.MockSendEmail != nil {
		return m.MockSendEmail(to, subject, body)
	}
	return nil
}
