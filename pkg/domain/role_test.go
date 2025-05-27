package domain_test

import (
	"testing"

	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/stretchr/testify/assert"
)

func TestParseRole(t *testing.T) {
	testCases := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		s       string
		want    domain.Role
		wantErr bool
	}{
		{
			name:    "Valid parsable role",
			s:       domain.RoleAdmin.String(),
			want:    domain.RoleAdmin,
			wantErr: false,
		},
		{
			name:    "Titlecase role",
			s:       "Admin",
			want:    "",
			wantErr: true,
		},
		{
			name:    "Invalid role",
			s:       "This is an invalid role",
			want:    "",
			wantErr: true,
		},
		{
			name:    "Empty string",
			s:       "",
			want:    "",
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, gotErr := domain.ParseRole(tc.s)
			if gotErr != nil {
				if !tc.wantErr {
					t.Errorf("ParseRole() failed: %v", gotErr)
				}
				return
			}
			if tc.wantErr {
				t.Fatal("ParseRole() succeeded unexpectedly")
			}
			assert.Equal(t, tc.want, got, "Expected role %v, got %v", tc.want, got)
		})
	}
}

func TestGetRolesFromStringSlice(t *testing.T) {
	testCases := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		strSlice []string
		want     []domain.Role
		wantErr  bool
	}{
		{
			name:     "Slice with valid roles",
			strSlice: []string{"admin", "operator"},
			want:     []domain.Role{domain.RoleAdmin, domain.RoleOperator},
			wantErr:  false,
		},
		{
			name:     "Empty slice",
			strSlice: []string{},
			want:     []domain.Role{},
			wantErr:  false,
		},
		{
			name:     "Slice with invalid role",
			strSlice: []string{"operator", "invalid_role"},
			want:     []domain.Role{},
			wantErr:  true,
		},
		{
			name:     "Nil slice",
			strSlice: nil,
			want:     []domain.Role{},
			wantErr:  true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, gotErr := domain.GetRolesFromStringSlice(tc.strSlice)
			if gotErr != nil {
				if !tc.wantErr {
					t.Errorf("GetRolesFromStringSlice() failed: %v", gotErr)
				}
				return
			}
			if tc.wantErr {
				t.Fatal("GetRolesFromStringSlice() succeeded unexpectedly")
			}
			assert.Equal(t, tc.want, got, "Expected string slice %v, got %v", tc.want, got)
		})
	}
}
