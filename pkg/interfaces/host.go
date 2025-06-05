package interfaces

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type IHostService interface {
	CreateHost(context.Context, *domain.Host) (*domain.Host, error)
	GetHostsByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*domain.Host, error)
	GetHostByID(ctx context.Context, ID uuid.UUID) (*domain.Host, error)
	GetDomainIPValues(string) (*domain.DomainIPResult, error)
	DeleteHostByID(ctx context.Context, ID uuid.UUID) (bool, error)
	PatchHostByID(context.Context, *domain.Host) (*domain.Host, error)
	ValidateHost(context.Context, string) error
	ValidateAlias(context.Context, string) error
}

type IHostHandlers interface {
	CreateHost(w http.ResponseWriter, req *http.Request) error
	GetHosts(w http.ResponseWriter, req *http.Request) error
	GetHostByID(w http.ResponseWriter, req *http.Request) error
	DeleteHostByID(w http.ResponseWriter, req *http.Request) error
	PatchHostByID(w http.ResponseWriter, req *http.Request) error
	ValidateHost(w http.ResponseWriter, req *http.Request) error
	ValidateAlias(w http.ResponseWriter, req *http.Request) error
}

type HostRepository interface {
	CreateHost(ctx context.Context, host *domain.Host) (*domain.Host, error)
	GetHostByID(context.Context, uuid.UUID) (*domain.Host, error)
	GetHostsByTenantID(ctx context.Context, tenantID uuid.UUID, hostsIDFilter []uuid.UUID) ([]*domain.Host, error)
	DeleteHostByID(context.Context, uuid.UUID) (bool, error)
	PatchHostByID(context.Context, domain.Host) (*domain.Host, error)
	AliasExists(context.Context, string) (bool, error)
}
