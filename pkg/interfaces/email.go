package interfaces

type IEmailService interface {
	SendEmail(to, subject, body string) error
}
