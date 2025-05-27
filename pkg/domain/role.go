package domain

import "fmt"

type Action string

const (
	// User Actions
	ActionUserGet Action = "user:get"

	// Host Actions
	ActionHostCreate        Action = "host:create"
	ActionHostValidate      Action = "host:validate"
	ActionHostValidateAlias Action = "host:validate_alias"
	ActionHostGetAll        Action = "host:get_all"
	ActionHostGetByID       Action = "host:get_by_id"
	ActionHostDeleteByID    Action = "host:delete_by_id"
	ActionHostPatchByID     Action = "host:patch_by_id"

	// Tenant Actions
	ActionTenantGetAll Action = "tenant:get_all"

	// Scan Actions
	ActionScanCreate                      Action = "scan:create"
	ActionScanCancelByID                  Action = "scan:cancel_by_id"
	ActionScanGetInsightsByID             Action = "scan:get_insights_by_id"
	ActionScanGetVulnerabilitiesByID      Action = "scan:get_vulnerabilities_by_id"
	ActionScanGetVulnerabilitySummaryByID Action = "scan:get_vulnerability_summary_by_id"
	ActionScanGetScorecardTrends          Action = "scan:get_scorecard_trends"

	// Scan Schedule Actions
	ActionScanScheduleDeleteByID Action = "scan_schedule:delete_by_id"
	ActionScanSchedulePatchByID  Action = "scan_schedule:patch_by_id"
	ActionScanScheduleGetAll     Action = "scan_schedule:get_all"

	// Report Actions
	ActionReportGetAll Action = "report:get_all"

	// Vulnerability Actions
	ActionVulnerabilityGet           Action = "vulnerability:get_by_id"
	ActionVulnerabilityCreateComment Action = "vulnerability:create_comment"
	ActionVulnerabilityPatchComment  Action = "vulnerability:patch_comment"
	ActionVulnerabilityDeleteComment Action = "vulnerability:delete_comment"

	// Dashboard Actions
	ActionDashboardGet Action = "dashboard:get"
)

func (a Action) String() string {
	return string(a)
}

type Role string

const (
	RoleOperator Role = "operator"
	RoleAnalyst  Role = "analyst"
	RoleAdmin    Role = "admin"
)

func (r Role) String() string {
	return string(r)
}

// actionRoles maps each action to the roles that are allowed to perform it.
// This is the source of truth for action-to-role mapping.
var actionRoles = map[Action][]Role{
	ActionUserGet: {RoleAdmin, RoleOperator, RoleAnalyst},

	ActionHostCreate:        {RoleOperator, RoleAnalyst},
	ActionHostValidate:      {RoleOperator, RoleAnalyst},
	ActionHostValidateAlias: {RoleOperator, RoleAnalyst},
	ActionHostGetAll:        {RoleAdmin, RoleOperator, RoleAnalyst},
	ActionHostGetByID:       {RoleAdmin, RoleOperator, RoleAnalyst},
	ActionHostDeleteByID:    {RoleAdmin, RoleOperator},
	ActionHostPatchByID:     {RoleAdmin, RoleOperator},

	ActionTenantGetAll: {RoleAdmin, RoleAnalyst},

	ActionScanCreate:                      {RoleOperator},
	ActionScanCancelByID:                  {RoleOperator},
	ActionScanGetInsightsByID:             {RoleOperator, RoleAnalyst},
	ActionScanGetVulnerabilitySummaryByID: {RoleOperator, RoleAnalyst},
	ActionScanGetVulnerabilitiesByID:      {RoleOperator, RoleAnalyst},
	ActionScanGetScorecardTrends:          {RoleOperator, RoleAnalyst},

	ActionScanScheduleDeleteByID: {RoleOperator, RoleAnalyst},
	ActionScanSchedulePatchByID:  {RoleOperator, RoleAnalyst},
	ActionScanScheduleGetAll:     {RoleOperator, RoleAnalyst},

	ActionReportGetAll: {RoleOperator, RoleAnalyst},

	ActionVulnerabilityGet:           {RoleOperator, RoleAnalyst},
	ActionVulnerabilityCreateComment: {RoleAnalyst},
	ActionVulnerabilityPatchComment:  {RoleAnalyst},
	ActionVulnerabilityDeleteComment: {RoleAnalyst},

	ActionDashboardGet: {RoleOperator, RoleAnalyst},
}

// AllActions is a slice containing all defined Action constants.
// This is populated automatically during package initialization.
var AllActions []Action

// roleActions maps each role to a slice of actions it is allowed to perform.
// This map is populated once during package initialization for efficient lookups.
var roleActions map[Role][]Action

// init function runs automatically when the package is initialized.
// It populates the roleActions map based on the actionRoles map
func init() {
	AllActions = make([]Action, 0)
	roleActions = make(map[Role][]Action)

	roleActions[RoleAdmin] = make([]Action, 0)
	roleActions[RoleOperator] = make([]Action, 0)
	roleActions[RoleAnalyst] = make([]Action, 0)

	for action, roles := range actionRoles {
		AllActions = append(AllActions, action)
		for _, role := range roles {
			roleActions[role] = append(roleActions[role], action)
		}
	}
}

func ParseRole(s string) (Role, error) {
	stringToRole := map[string]Role{
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
	res := make([]Role, 0)
	if strSlice == nil {
		return res, fmt.Errorf("string slice must not be nil: %v", strSlice)
	}

	for _, s := range strSlice {
		v, err := ParseRole(s)
		if err != nil {
			return nil, err
		}
		res = append(res, v)

	}

	return res, nil
}

func GetValidRolesForAction(action Action) ([]Role, error) {
	v, ok := actionRoles[action]
	if !ok {
		return nil, fmt.Errorf("%s has no defined roles", action.String())
	}

	return v, nil
}

// GetValidActionsForRole returns a slice of all actions that a given role is permitted to perform.
// If the role is not defined in the system, it returns an empty slice.
// It returns a copy of the internal slice to avoid modifications.
func GetValidActionsForRole(role Role) []Action {
	if actions, ok := roleActions[role]; ok {
		copiedActions := make([]Action, len(actions))
		copy(copiedActions, actions)
		return copiedActions
	}
	return []Action{}
}

// GetDeniedActionsForRole calculates and returns a slice of actions that the given role is not allowed to perform.
// This is based on the difference between all possible actions and the allowed actions for the role.
// It returns a copy of the slice to prevent external modifications.
func GetDeniedActionsForRole(role Role) []Action {
	// 1. Get all allowed actions
	allowedActions := GetValidActionsForRole(role)

	// 2. Create a set of allowed actions for efficient lookup
	allowedSet := make(map[Action]bool)
	for _, a := range allowedActions {
		allowedSet[a] = true
	}

	// 3. Iterate through all possible actions and identify those not in set
	deniedActions := make([]Action, 0)
	for _, a := range AllActions {
		if !allowedSet[a] {
			deniedActions = append(deniedActions, a)
		}
	}
	copiedDeniedActions := make([]Action, len(deniedActions))
	copy(copiedDeniedActions, deniedActions)
	return copiedDeniedActions
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
