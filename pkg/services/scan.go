package services

import (
	"fmt"
	"github.com/kptm-tools/common/common/events"
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
	err  string // you must use error type here
}

func (s ScanService) CreateScans(hostIDs []string) (*domain.Scan, error) {
	scanDB := domain.NewScan()

	var wg sync.WaitGroup
	var results []resultChannel
	ch := make(chan resultChannel)

	for _, hostID := range hostIDs {
		wg.Add(1)
		go launchEvent(s.storage, ch, &wg, hostID)
	}
	go func() {
		for v := range ch {
			results = append(results, v)
		}
	}()

	wg.Wait()
	close(ch)
	// set results of host in status scan
	metadataWhois := &domain.Metadata{
		Progress: "0%",
		Service:  "Whois",
	}
	metadataHarvester := &domain.Metadata{
		Progress: "0%",
		Service:  "Harvester",
	}
	metadataDNSLookup := &domain.Metadata{
		Progress: "0%",
		Service:  "DNSLookup",
	}
	for _, result := range results {
		if result.err != "" {
			return nil, fmt.Errorf(result.err)
		}
		hostValue := ""
		hostType := *new(events.TargetType)
		if result.data.IP == "" {
			hostType = events.Domain
			hostValue = result.data.Domain
		} else {
			hostType = events.IP
			hostValue = result.data.IP
		}
		target := &events.Target{
			Alias: result.data.Name,
			Value: hostValue,
			Type:  hostType,
		}

		hostStatus := &domain.StatusHost{
			Host:     result.data.Name,
			Metadata: []*domain.Metadata{metadataHarvester, metadataWhois, metadataDNSLookup},
		}
		scanDB.HostsStatus = append(scanDB.HostsStatus, *hostStatus)
		scanDB.Targets = append(scanDB.Targets, *target)
	}
	dataScan, error := s.storage.CreateScan(scanDB)
	dataScan.Targets = scanDB.Targets
	if error != nil {
		return nil, error
	}
	return dataScan, nil
}

func launchEvent(s interfaces.IStorage, ch chan resultChannel, wg *sync.WaitGroup, hostID string) {
	defer wg.Done()

	if hostID == "" {
		ch <- resultChannel{err: fmt.Sprintf("error: got HostID empty")}
		return
	}
	host, err := s.GetHostByID(hostID)
	if err != nil {
		return
	}
	ch <- resultChannel{data: *host}
}
