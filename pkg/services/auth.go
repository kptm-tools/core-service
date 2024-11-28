package services

import "github.com/kptm-tools/core-service/pkg/interfaces"

type AuthService struct {
}

var _ interfaces.IAuthService = (*AuthService)(nil)

func NewAuthService() *AuthService {
	return &AuthService{}
}

func (s *AuthService) Login(email, password, applicationID string) error {

	// Connect to fusionauth and return the response
	return nil
}
