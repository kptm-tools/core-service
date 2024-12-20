package interfaces

import (
	"net/http"

	"github.com/kptm-tools/core-service/pkg/domain"
)

type IHostService interface {
	CreateHost(*domain.Host) (*domain.Host, error)
	GetHostsByTenantIDAndUserID(tenantID string, userID string) ([]*domain.Host, error)
	GetHostByID(ID string) (*domain.Host, error)
	GetHostname(string) string
	DeleteHostByID(ID string) (bool, error)
	PatchHostByID(ID, domainName, ip, alias string, credential, rapporteur []byte) (*domain.Host, error)
}

type IHostHandlers interface {
	CreateHost(w http.ResponseWriter, req *http.Request) error
	GetHostsByTenantIDAndUserID(w http.ResponseWriter, req *http.Request) error
	GetHostByID(w http.ResponseWriter, req *http.Request) error
	DeleteHostByID(w http.ResponseWriter, req *http.Request) error
	PatchHostByID(w http.ResponseWriter, req *http.Request) error
}
