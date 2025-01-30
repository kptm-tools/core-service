package interfaces

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type IStorage interface {
	CreateHost(*domain.Host) (*domain.Host, error)
	GetHostsByTenantIDAndUserID(string, string) ([]*domain.Host, error)
	GetHostByID(int) (*domain.Host, error)
	DeleteHostByID(int) (bool, error)
	PatchHostByID(*domain.Host) (*domain.Host, error)
	CreateTenant(*domain.Tenant) (*domain.Tenant, error)
	GetTenants() ([]*domain.Tenant, error)
	Ping() error
	CreateScans(*domain.Scan, []int) ([]*domain.Scan, error)
	ExistAlias(string) (bool, error)
	GetScans(tenantID string) ([]*domain.ScanSummary, error)
	InsertScanResult(*sql.Tx, *domain.ScanResult) error
	InsertVulnerabilityResult(*domain.ScanResult) error
	UpdateScanStatus(scanID uuid.UUID, status string) error
	UpdateScanStatusAndEndedAt(tx *sql.Tx, scanID uuid.UUID, status string, endedAt time.Time) error
	GetScanInsights(scanID uuid.UUID) (*domain.ScanInsights, error)
	GetProtectionScore(scanID uuid.UUID) (float64, error)
}
