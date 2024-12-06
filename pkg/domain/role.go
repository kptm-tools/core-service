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

func parseRole(s string) (Role, error) {
	var stringToRole = map[string]Role{
		"operator": RoleOperator,
		"analyst":  RoleAnalyst,
		"admin":    RoleAdmin,
	}

	v, ok := stringToRole[s]

	if !ok {
		return "", fmt.Errorf("Invalid role: `%s`\n", s)
	}

	return v, nil
}

func GetRolesFromStringSlice(strSlice []string) ([]Role, error) {
	var res []Role
	for _, s := range strSlice {
		v, err := parseRole(s)

		if err != nil {
			return nil, err
		}
		res = append(res, v)

	}

	return res, nil
}

func GetValidRoles(funcName string) ([]Role, error) {

	funcRoles := map[string][]Role{
		"handleHealthcheck-fm": {RoleAdmin},
		"targets":              {RoleAdmin, RoleOperator, RoleAnalyst},
		"tenants":              {RoleAdmin, RoleAnalyst},
		"getUser":              {RoleAdmin, RoleOperator, RoleAnalyst},
	}

	v, ok := funcRoles[funcName]

	if !ok {
		return nil, fmt.Errorf("`%s` has no defined roles", funcName)
	}

	return v, nil

}

// function for finding the intersection of two arrays
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
