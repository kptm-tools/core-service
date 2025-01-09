package services

import (
	"fmt"

	"github.com/kptm-tools/common/common/events"
	"github.com/kptm-tools/common/common/results"
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

func (s ScanService) CreateScans(hostIDs []int) (*domain.Scan, error) {
	scanDB := domain.NewScan()
	metadataDefault := createMetadata()

	for _, hostID := range hostIDs {
		host, err := s.storage.GetHostByID(hostID)
		if err != nil {
			return nil, fmt.Errorf("failed to get host: %w", err)
		}

		// Process the host data into the scan
		scanDB.HostsStatus = append(scanDB.HostsStatus, createHostStatus(*host, metadataDefault))
		scanDB.Targets = append(scanDB.Targets, createTarget(*host))
	}

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
		Service:  results.ServiceWhoIs,
	}
	metadataHarvester := domain.Metadata{
		Progress: "0%",
		Service:  results.ServiceHarvester,
	}
	metadataDNSLookup := domain.Metadata{
		Progress: "0%",
		Service:  results.ServiceDNSLookup,
	}
	metadataNmap := domain.Metadata{
		Progress: "0%",
		Service:  results.ServiceNmap,
	}
	return []domain.Metadata{metadataHarvester, metadataWhois, metadataDNSLookup, metadataNmap}
}

func createTarget(host domain.Host) events.Target {
	var hostValue string
	var hostType events.TargetType
	if host.Domain == "" {
		hostType = events.IP
		hostValue = host.IP
	} else {
		hostType = events.Domain
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
