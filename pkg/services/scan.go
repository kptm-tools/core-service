package services

import (
	"fmt"

	"github.com/kptm-tools/common/common/enums"
	"github.com/kptm-tools/common/common/events"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type ScanService struct {
	storage interfaces.IStorage
}

var _ interfaces.IScanService = (*ScanService)(nil)

func NewScanService(storage interfaces.IStorage) *ScanService {
	return &ScanService{
		storage: storage,
	}
}

func (s ScanService) CreateScans(hostIDs []int, tenantID, operatorID string) (*domain.Scan, error) {
	scanDB := domain.NewScan()
	scanDB.TenantID = tenantID
	scanDB.OperatorID = operatorID

	for _, hostID := range hostIDs {
		host, err := s.storage.GetHostByID(hostID)
		if err != nil {
			return nil, fmt.Errorf("failed to get host: %w", err)
		}

		scanDB.Targets = append(scanDB.Targets, createTarget(*host))
	}
	scanDB.HostIDs = hostIDs
	dataScan, err := s.storage.CreateScan(scanDB)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan: %w", err)
	}

	dataScan.Targets = scanDB.Targets
	return dataScan, nil
}

func createMetadata() []domain.Metadata {
	// set dataResults of host in status scan
	metadataWhois := domain.Metadata{
		Progress: "0%",
		Service:  enums.ServiceWhoIs,
	}
	metadataHarvester := domain.Metadata{
		Progress: "0%",
		Service:  enums.ServiceHarvester,
	}
	metadataDNSLookup := domain.Metadata{
		Progress: "0%",
		Service:  enums.ServiceDNSLookup,
	}
	metadataNmap := domain.Metadata{
		Progress: "0%",
		Service:  enums.ServiceNmap,
	}
	return []domain.Metadata{metadataHarvester, metadataWhois, metadataDNSLookup, metadataNmap}
}

func createTarget(host domain.Host) events.Target {
	var hostValue string
	var hostType enums.TargetType
	if host.Domain == "" {
		hostType = enums.IP
		hostValue = host.IP
	} else {
		hostType = enums.Domain
		hostValue = host.Domain
	}

	target := events.Target{
		Alias: host.Name,
		Value: hostValue,
		Type:  hostType,
	}
	return target
}

func createHostStatus(host domain.Host, metadata []domain.Metadata) domain.StatusHost {
	hostStatus := domain.StatusHost{
		Host:     host.Name,
		Metadata: metadata,
	}
	return hostStatus
}

func (s ScanService) GetScans(tenantID string) ([]*domain.ScanSummary, error) {
	return s.storage.GetScans(tenantID)
}
