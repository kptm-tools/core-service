package services

import (
	"fmt"
	"github.com/kptm-tools/common/common/events"
	"github.com/kptm-tools/common/common/results"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"sync"
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

type resultChannel struct {
	data domain.Host
	err  error
}

func (s ScanService) CreateScans(hostIDs []string) (*domain.Scan, error) {
	scanDB := domain.NewScan()
	dataResults, err := launchScanEvents(s.storage, hostIDs)
	if err != nil {
		return nil, err
	}
	metadataDefault := createMetadata()
	for _, result := range dataResults {
		if result.err != nil {
			return nil, result.err
		}
		scanDB.HostsStatus = append(scanDB.HostsStatus, *createHostStatus(result.data, metadataDefault))
		scanDB.Targets = append(scanDB.Targets, *createTarget(result.data))
	}
	dataScan, err := s.storage.CreateScan(scanDB)
	dataScan.Targets = scanDB.Targets
	if err != nil {
		return nil, err
	}
	return dataScan, nil
}

func launchEvent(s interfaces.IStorage, ch chan resultChannel, wg *sync.WaitGroup, hostID string) {
	defer wg.Done()

	if hostID == "" {
		ch <- resultChannel{err: fmt.Errorf("hostID is empty")}
		return
	}
	host, err := s.GetHostByID(hostID)
	if err != nil {
		ch <- resultChannel{err: fmt.Errorf("failed to get host: %w", err)}
		return
	}
	ch <- resultChannel{data: *host}
}
func createMetadata() []*domain.Metadata {
	// set dataResults of host in status scan
	metadataWhois := &domain.Metadata{
		Progress: "0%",
		Service:  results.ServiceWhoIs,
	}
	metadataHarvester := &domain.Metadata{
		Progress: "0%",
		Service:  results.ServiceHarvester,
	}
	metadataDNSLookup := &domain.Metadata{
		Progress: "0%",
		Service:  results.ServiceDNSLookup,
	}
	metadataNmap := &domain.Metadata{
		Progress: "0%",
		Service:  results.ServiceNmap,
	}
	return []*domain.Metadata{metadataHarvester, metadataWhois, metadataDNSLookup, metadataNmap}
}

func createTarget(host domain.Host) *events.Target {
	hostValue := ""
	hostType := *new(events.TargetType)
	if host.IP == "" {
		hostType = events.Domain
		hostValue = host.Domain
	} else {
		hostType = events.IP
		hostValue = host.IP
	}
	target := &events.Target{
		Alias: host.Name,
		Value: hostValue,
		Type:  hostType,
	}
	return target
}

func createHostStatus(host domain.Host, metadata []*domain.Metadata) *domain.StatusHost {
	hostStatus := &domain.StatusHost{
		Host:     host.Name,
		Metadata: metadata,
	}
	return hostStatus
}

func launchScanEvents(storage interfaces.IStorage, hostIDs []string) ([]resultChannel, error) {
	var wg sync.WaitGroup
	var dataResults []resultChannel
	ch := make(chan resultChannel, len(hostIDs))

	for _, hostID := range hostIDs {
		wg.Add(1)
		go launchEvent(storage, ch, &wg, hostID)
	}
	go func() {
		for v := range ch {
			dataResults = append(dataResults, v)
		}
	}()
	wg.Wait()
	close(ch)
	return dataResults, nil
}
