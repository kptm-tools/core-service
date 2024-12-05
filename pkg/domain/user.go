package domain

type User struct {
	ID            string   `json:"id"`
	Email         string   `json:"email"`
	Password      string   `json:"password"`
	ApplicationID string   `json:"application_id"`
	Roles         []string `json:"roles"`
}

func NewUser(id, email, password, tenantID, appID string, roles []string) *User {
	return &User{
		ID:            id,
		Email:         email,
		Password:      password,
		ApplicationID: appID,
		Roles:         roles,
	}
}
