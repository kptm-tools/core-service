package domain

type UserPersonalInfo struct {
	Name     string `json:"name"`
	Lastname string `json:"lastname"`
}
type User struct {
	ID            string           `json:"id"`
	Email         string           `json:"email"`
	Password      string           `json:"password"`
	ApplicationID string           `json:"application_id"`
	Roles         []string         `json:"roles"`
	User          UserPersonalInfo `json:"user"`
}

func NewUser(id, email, password, tenantID, appID string, roles []string, name string, lastname string) *User {
	return &User{
		ID:            id,
		Email:         email,
		Password:      password,
		ApplicationID: appID,
		Roles:         roles,
		User: UserPersonalInfo{
			Name:     name,
			Lastname: lastname,
		},
	}
}
