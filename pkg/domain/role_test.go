package domain_test

import (
	"sort"
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

func TestGetValidRolesForAction(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		action  domain.Action
		want    []domain.Role
		wantErr bool
	}{
		{
			name:    "Valid Action",
			action:  domain.ActionDashboardGet,
			want:    []domain.Role{domain.RoleAdmin, domain.RoleOperator, domain.RoleAnalyst},
			wantErr: false,
		},
		{
			name:    "Invalid Action",
			action:  "Non-existant action",
			want:    []domain.Role{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := domain.GetValidRolesForAction(tt.action)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("GetValidRolesForAction() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("GetValidRolesForAction() succeeded unexpectedly")
			}
			assert.Equal(t, tt.want, got, "Got role slice %v, expected %v", got, tt.want)
		})
	}
}

func TestGetValidActionsForRole(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		role domain.Role
		want []domain.Action
	}{
		{
			name: "Valid Role",
			role: domain.RoleAdmin,
			want: domain.AllActions,
		},
		{
			name: "Invalid Role returns empty slice",
			role: "Invalid Role",
			want: []domain.Action{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := domain.GetValidActionsForRole(tt.role)
			assert.Equal(t, len(tt.want), len(got), "Expected actions slice to be the same length")

			// Sort them, since we're comparing values and the map operation won't produce the same order each time
			sort.Slice(tt.want, func(i, j int) bool {
				return tt.want[i].String() < tt.want[j].String()
			})
			sort.Slice(got, func(i, j int) bool {
				return got[i].String() < got[j].String()
			})
			assert.Equal(t, tt.want, got, "Expected actions slice %v, got %v", tt.want, got)
		})
	}
}
