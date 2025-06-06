package services_test

import (
	"testing"

	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/services"
	"github.com/stretchr/testify/assert"
)

func TestAuthService_GetDeniedActionsForRoles(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for receiver constructor.
		// Named input parameters for target function.
		roles []domain.Role
		want  []domain.Action
	}{
		{
			name:  "Admin role",
			roles: []domain.Role{domain.RoleAdmin},
			want:  []domain.Action{},
		},
		{
			name:  "Admin and Operator Role",
			roles: []domain.Role{domain.RoleAdmin, domain.RoleOperator},
			want:  []domain.Action{},
		},
		{
			name:  "Empty Role Slice",
			roles: []domain.Role{},
			want:  domain.AllActions,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := services.NewAuthService()
			got := s.GetDeniedActionsForRoles(tt.roles)
			assert.Equal(t, tt.want, got, "Expected actions %v for roles %v, got %v", tt.want, tt.roles, got)
		})
	}
}
