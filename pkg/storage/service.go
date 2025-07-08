package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	repository "github.com/kptm-tools/core-service/db"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type ServiceRepo struct {
	defaultQueries *repository.Queries
}

var _ interfaces.ServiceRepository = (*ServiceRepo)(nil)

func NewServiceRepository(queries *repository.Queries) *ServiceRepo {
	return &ServiceRepo{
		defaultQueries: queries,
	}
}

// getQueries retrieves the correct *repository.Queries instance from the context.
// If a transaction is active, it gets the transactional queries. Otherwise, it uses
// the defaultQueries.
func (r *ServiceRepo) getQueries(ctx context.Context) *repository.Queries {
	return GetQueriesFromContext(ctx, r.defaultQueries)
}

func (r *ServiceRepo) CreateOrUpdateService(
	ctx context.Context,
	hostID uuid.UUID,
	scanID uuid.UUID,
	portData tools.PortData,
) (*domain.Service, error) {
	queries := r.getQueries(ctx)

	params := repository.CreateOrUpdateServiceParams{
		HostID:     hostID,
		ScanID:     scanID,
		Port:       int32(portData.ID),
		Protocol:   sql.NullString{String: portData.Protocol, Valid: portData.Protocol != ""},
		SvName:     sql.NullString{String: portData.Service.Name, Valid: portData.Service.Name != ""},
		SvVersion:  sql.NullString{String: portData.Service.Version, Valid: portData.Service.Version != ""},
		Confidence: sql.NullInt32{Int32: int32(portData.Service.Confidence), Valid: portData.Service.Confidence != 0},
		Cpe:        sql.NullString{String: portData.Service.CPE, Valid: portData.Service.CPE != ""},
		Product:    sql.NullString{String: portData.Product, Valid: portData.Product != ""},
		PortState:  repository.PortStateEnum(portData.State),
	}
	slog.Debug(
		"Service processed (created or updated)",
		slog.String("scan_id", scanID.String()),
		slog.String("host_id", hostID.String()),
		slog.String("service_cpe", portData.Service.CPE),
		slog.Int("service_port", int(portData.ID)),
	)
	dbService, err := queries.CreateOrUpdateService(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to query service: %w", err)
	}

	domService := toDomainService(dbService)

	return &domService, nil
}

func (r *ServiceRepo) GetServiceByID(ctx context.Context, svcID int32) (*domain.Service, error) {
	queries := r.getQueries(ctx)
	dbService, err := queries.GetServiceByID(ctx, svcID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, customerrors.ErrServiceNotFound
		}

		return nil, fmt.Errorf("failed to query service: %w", err)
	}
	domService := toDomainService(dbService)
	return &domService, nil
}

func toDomainService(dbService repository.Service) domain.Service {
	return domain.Service{
		ID:         dbService.ID,
		HostID:     dbService.HostID,
		ScanID:     dbService.ScanID,
		Port:       dbService.Port,
		Protocol:   dbService.Protocol.String, // .String for sql.NullString
		SvName:     dbService.SvName.String,
		SvVersion:  dbService.SvVersion.String,
		Confidence: dbService.Confidence.Int32, // .Int32 for sql.NullInt32
		CPE:        dbService.Cpe.String,
		Product:    dbService.Product.String,
		PortState:  string(dbService.PortState), // Convert PortStateEnum to string
		CreatedAt:  dbService.CreatedAt.Time,    // .Time for sql.NullTime
		UpdatedAt:  dbService.UpdatedAt.Time,
	}
}

func (r *ServiceRepo) GetServiceByScanHostPortProtocol(ctx context.Context, hostID uuid.UUID, scanID uuid.UUID, port int32, protocol string) (*domain.Service, error) {
	queries := r.getQueries(ctx)
	params := repository.GetServiceByScanIDAndHostIDAndPortAndProtocolParams{
		ScanID:   scanID,
		HostID:   hostID,
		Port:     port,
		Protocol: sql.NullString{String: protocol, Valid: true},
	}
	dbService, err := queries.GetServiceByScanIDAndHostIDAndPortAndProtocol(ctx, params)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, customerrors.ErrServiceNotFound
		}
		return nil, fmt.Errorf("failed to query service: %w", err)
	}
	domService := toDomainService(dbService)
	return &domService, nil
}
