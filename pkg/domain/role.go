package domain

import "fmt"

type Role string

const (
	RoleOperator Role = "operator"
	RoleAnalyst  Role = "analyst"
	RoleAdmin    Role = "admin"
)

func (r Role) String() string {
	return string(r)
}

func ParseRole(s string) (Role, error) {
	var stringToRole = map[string]Role{
		"operator": RoleOperator,
		"analyst":  RoleAnalyst,
		"admin":    RoleAdmin,
	}

	v, ok := stringToRole[s]

	if !ok {
		return "", fmt.Errorf("invalid role: `%s`", s)
	}

	return v, nil
}

func GetRolesFromStringSlice(strSlice []string) ([]Role, error) {
	var res []Role
	for _, s := range strSlice {
		v, err := ParseRole(s)

		if err != nil {
			return nil, err
		}
		res = append(res, v)

	}

	return res, nil
}

func GetValidRoles(funcName string) ([]Role, error) {

	funcRoles := map[string][]Role{
		"handleHealthcheck-fm":    {RoleAdmin},
		"targets":                 {RoleAdmin, RoleOperator, RoleAnalyst},
		"tenants":                 {RoleAdmin, RoleAnalyst},
		"getUser":                 {RoleAdmin, RoleOperator, RoleAnalyst},
		"newHost":                 {RoleOperator, RoleAnalyst},
		"getHostsByTenantAndUser": {RoleAdmin, RoleOperator, RoleAnalyst},
		"getHostByID":             {RoleAdmin, RoleOperator, RoleAnalyst},
		"deleteHostByID":          {RoleAdmin, RoleOperator},
		"patchHostByID":           {RoleAdmin, RoleOperator},
	}

	v, ok := funcRoles[funcName]

	if !ok {
		return nil, fmt.Errorf("`%s` has no defined roles", funcName)
	}

	return v, nil

}

// ContainsRole finds the intersection of two arrays
// of type Role, returns an array with the intersection
func ContainsRole(roles []Role, rolesToCheck []Role) []Role {
	intersection := make([]Role, 0)

	set := make(map[Role]bool)

	// Create a set from the first array
	for _, role := range roles {
		set[role] = true // setting the initial value to true
	}

	// Check elements in the second array against the set
	for _, role := range rolesToCheck {

		if set[role] {
			intersection = append(intersection, role)
		}
	}

	return intersection
}
