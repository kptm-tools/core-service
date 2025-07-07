package dto

import (
	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type ClientMessageType string

const (
	MessageInitialRequest ClientMessageType = "initial_data_request"
	MessageVectorUpdate   ClientMessageType = "vector_update"
	MessageSelectVector   ClientMessageType = "select_vector"
	MessageApplyVectors   ClientMessageType = "apply_vectors_request"
)

func (s ClientMessageType) String() string {
	return string(s)
}

// InitialDataRequest is the payload send in a MessageInitialRequest (Client -> Server)
type InitialDataRequest struct {
	ScanID string `json:"scan_id"`
}

// SelectVectorRequest is the payload sent in a MessageSelectVector (Client -> Server)
type SelectVectorRequest struct {
	VulnerabilityTypeName string `json:"vulnerability_type_name"`
}

type CreateHostRequest struct {
	Value       string              `json:"value"`
	Name        string              `json:"name"`
	ValueType   string              `json:"value_type"`
	Credentials []domain.Credential `json:"credentials"`
	Rapporteurs []domain.Rapporteur `json:"rapporteurs"`
}

type ValidateHostRequest struct {
	Value string `json:"value"`
}

type ValidateAliasRequest struct {
	Hostname string `json:"hostname"`
}

type GetHostByTenantIDRequest struct {
	TenantID string `json:"tenant_id"`
}

// LoginRequest holds the data required for user authentication.
// @name LoginRequest
type LoginRequest struct {
	// LoginID is the user's identifier, usually their email.
	// example: admin@example.com
	LoginID string `json:"loginId" binding:"required"`

	// Password is the user's plaintext password.
	// example: password
	Password string `json:"password" binding:"required"`

	// ApplicationID is the UUID of the application requesting authentication.
	// example: 00000000-1111-0000-0000-000000000000
	ApplicationID string `json:"application_id" binding:"required"`
}

type RegisterTenantRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type ForgotPasswordRequest struct {
	LoginID       string `json:"login_id"`
	ApplicationID string `json:"application_id"`
}

type ChangePasswordRequest struct {
	LoginID          string `json:"login_id"`
	Password         string `json:"password"`
	ChangePasswordID string `json:"change_password_id"`
	ApplicationID    string `json:"application_id"`
}

type VerifyEmailRequest struct {
	VerificationID string `json:"verification_id"`
}

type RegisterUserRequest struct {
	FirstName string   `json:"firstname"`
	LastName  string   `json:"lastname"`
	Email     string   `json:"email"`
	Password  string   `json:"password"`
	Roles     []string `json:"roles"`

	ApplicationID string `json:"application_id"`
}

type ServiceHost struct {
	Names []string `json:"names"`
	Host  string   `json:"host"`
}
type ScanRequest struct {
	HostID     uuid.UUID              `json:"host_id"`
	ScheduleAt *string                `json:"schedule_at"`
	Frequency  *domain.RepeatSchedule `json:"repeat_frequency"`
}

type ScanScheduleRequest struct {
	ScheduleAt *string                `json:"schedule_at"`
	Frequency  *domain.RepeatSchedule `json:"repeat_frequency"`
}

type VulnerabilityCommentRequest struct {
	Comment string `json:"comment"`
}
