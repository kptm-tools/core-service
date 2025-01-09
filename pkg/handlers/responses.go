package handlers

import (
	"github.com/kptm-tools/core-service/pkg/domain"
)

type RegisterTenantResponse struct {
	ApplicationID string      `json:"application_id"`
	User          domain.User `json:"user"`
}
