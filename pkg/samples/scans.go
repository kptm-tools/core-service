package samples

import (
	"strconv"
	"time"

	"github.com/brianvoe/gofakeit/v7"

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

func SampleScans(size int, tenants []domain.Tenant, hosts []domain.Host) []domain.Scan {
	operators, _, targets := generateDefaultConstants()

	fromYears := 1
	domainScans := make([]domain.Scan, size)
	for i := range size {
		var hostValue string
		var targetType enums.TargetType
		indexTenant := gofakeit.Number(0, len(tenants)-1)
		indexTarget := gofakeit.Number(0, len(targets)-1)
		hostsTenantOperator := getHostsFromTenant(hosts, tenants[indexTenant], operators[indexTenant])
		host := hostsTenantOperator[gofakeit.Number(0, len(hostsTenantOperator)-1)]

		if targets[indexTarget] == "ip" {
			hostValue = host.IP
			targetType = enums.IP
		} else if targets[indexTarget] == "domain" {
			hostValue = host.Name
			targetType = enums.Domain
		} else {
			hostValue = host.Name
			targetType = enums.Subdomain
		}
		month := gofakeit.Month()
		day := gofakeit.Day()
		creationTime := gofakeit.DateRange(time.Now().AddDate(-fromYears, 0, 0), time.Now().AddDate(-fromYears, month, day)).UTC()
		endedTime := creationTime.Add(time.Minute * time.Duration(gofakeit.IntRange(1, 100)))
		domainScans[i] = domain.Scan{
			ID:         uuid.New(),
			TenantID:   tenants[indexTenant].ID,
			OperatorID: operators[indexTenant],
			HostID:     host.ID,
			// HostsStatus: []domain.StatusHost{
			// 	{
			// 		Host:     hostValue,
			// 		Metadata: GenerateMetaData(gofakeit.Number(1, 4), services),
			// 	},
			// },
			// HostsResults: []domain.ResultHost{
			// 	{Host: hostValue},
			// },
			Target: results.Target{
				Alias: host.Name,
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

func getHostsFromTenant(hosts []domain.Host, tenant domain.Tenant, operatorID uuid.UUID) []domain.Host {
	var domainHosts []domain.Host
	for _, host := range hosts {
		if host.TenantID == tenant.ID && host.OperatorID == operatorID {
			domainHosts = append(domainHosts, host)
		}
	}
	return domainHosts
}

func generateDefaultConstants() ([]uuid.UUID, []string, []string) {
	operators := make([]uuid.UUID, 2)
	services := make([]string, 4)
	targets := make([]string, 3)
	operators[0] = uuid.MustParse("00000000-0000-0000-0000-111111111111")
	operators[1] = uuid.MustParse("00000000-0000-0000-0000-222222222222")
	services[0] = "nmap"
	services[1] = "whois"
	services[2] = "dns_lookup"
	services[3] = "harvester"
	targets[0] = "domain"
	targets[1] = "subddomain"
	targets[2] = "ip"
	return operators, services, targets
}
