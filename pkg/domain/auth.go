package domain

type User struct {
	Email         string
	Password      string
	ApplicationID string
}

func NewUser(email, password, applicationID string) *User {
	return &User{
		Email:         email,
		Password:      password,
		ApplicationID: applicationID,
	}
}
