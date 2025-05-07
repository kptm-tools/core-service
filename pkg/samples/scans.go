package samples

import (
	"github.com/brianvoe/gofakeit/v7"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results"
	"github.com/kptm-tools/core-service/pkg/domain"
)

func GenerateMetaData(size int, services []string) []domain.Metadata {
	metadata := make([]domain.Metadata, size)
	indexService := gofakeit.Number(0, 3)
	for i := range size {
		metadata[i] = domain.Metadata{
			Progress: strconv.Itoa(gofakeit.Number(1, 100)) + "%",
			Service:  enums.EventSubjectName(services[indexService]),
		}
	}
	return metadata
}

func SampleScans(size int, tenants []domain.Tenant, hostsSize int) []domain.Scan {
	operators, services, targets := GenerateDefaultConstants()
	fromYears := 1
	domainScans := make([]domain.Scan, size)
	for i := range size {
		var hostValue string
		var alias string
		var targetType enums.TargetType
		indexTenant := gofakeit.Number(0, len(tenants)-1)
		indexTarget := gofakeit.Number(0, len(targets)-1)
		if targets[indexTarget] == "ip" {
			hostValue = gofakeit.IPv4Address()
			alias = "Private IP"
			targetType = enums.IP
		} else if targets[indexTarget] == "domain" {
			hostValue = gofakeit.DomainName()
			alias = strings.Split(hostValue, ".")[0]
			targetType = enums.Domain
		} else {
			hostValue = gofakeit.DomainName()
			alias = strings.Split(hostValue, ".")[0]
			targetType = enums.Subdomain
		}
		hostID := gofakeit.Number(1, hostsSize)
		month := gofakeit.Month()
		day := gofakeit.Day()
		creationTime := gofakeit.DateRange(time.Now().AddDate(-fromYears, 0, 0), time.Now().AddDate(-fromYears, month, day)).UTC()
		endedTime := creationTime.Add(time.Duration(gofakeit.IntRange(1, 100)))
		domainScans[i] = domain.Scan{
			ID:         uuid.New(),
			TenantID:   tenants[indexTenant].ProviderID,
			OperatorID: operators[indexTenant],
			HostID:     hostID,
			HostsStatus: []domain.StatusHost{
				{
					Host:     hostValue,
					Metadata: GenerateMetaData(gofakeit.Number(1, 4), services),
				},
			},
			HostsResults: []domain.ResultHost{
				{Host: hostValue},
			},
			Target: results.Target{
				Alias: alias,
				Value: hostValue,
				Type:  targetType,
			},
			CreatedAt: creationTime,
			UpdatedAt: endedTime,
			StartedAt: creationTime,
			EndedAt:   &endedTime,
			Status:    enums.StatusCompleted.String(),
		}
	}
	return domainScans
}

func GenerateDefaultConstants() ([]string, []string, []string) {
	operators := make([]string, 2)
	services := make([]string, 4)
	targets := make([]string, 3)
	operators[0] = "00000000-0000-0000-0000-111111111111"
	operators[1] = "00000000-0000-0000-0000-222222222222"
	services[0] = "nmap"
	services[1] = "whois"
	services[2] = "dns_lookup"
	services[3] = "harvester"
	targets[0] = "domain"
	targets[1] = "subddomain"
	targets[2] = "ip"
	return operators, services, targets
}
