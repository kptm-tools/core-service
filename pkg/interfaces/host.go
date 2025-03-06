package interfaces

import (
	"net/http"

	"github.com/kptm-tools/core-service/pkg/domain"
)

type IHostService interface {
	CreateHost(*domain.Host) (*domain.Host, error)
	GetHostsByTenantID(tenantID string) ([]*domain.Host, error)
	GetHostByID(ID int) (*domain.Host, error)
	GetHostNameFromIP(string) ([]string, error)
	GetDomainIPValues(string) (*domain.DomainIPResult, error)
	DeleteHostByID(ID int) (bool, error)
	PatchHostByID(*domain.Host) (*domain.Host, error)
	ValidateHost(string) error
	ValidateAlias(string) error
	GetTenantDashboardData(tenantID string) (*domain.TenantDashboardData, error)
}

type IHostHandlers interface {
	CreateHost(w http.ResponseWriter, req *http.Request) error
	GetHosts(w http.ResponseWriter, req *http.Request) error
	GetHostByID(w http.ResponseWriter, req *http.Request) error
	DeleteHostByID(w http.ResponseWriter, req *http.Request) error
	PatchHostByID(w http.ResponseWriter, req *http.Request) error
	ValidateHost(w http.ResponseWriter, req *http.Request) error
	ValidateAlias(w http.ResponseWriter, req *http.Request) error
	GetDashboard(w http.ResponseWriter, req *http.Request) error
}
