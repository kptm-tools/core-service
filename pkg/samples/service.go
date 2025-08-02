package samples

import (
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/kptm-tools/common/common/pkg/results/tools"
)

// serviceProfile is a helper struct to generate sample portData
type serviceProfile struct {
	PortID      uint16
	Protocol    string
	ServiceName string
	Product     string
	Version     string
	CPE         string
}

var predefinedServiceProfiles = []serviceProfile{
	{PortID: 21, Protocol: "tcp", ServiceName: "ftp", Product: "vsftpd", Version: "3.0.3", CPE: "cpe:/a:vsftpd:vsftpd:3.0.3"},
	{PortID: 22, Protocol: "tcp", ServiceName: "ssh", Product: "OpenSSH", Version: "8.9p1", CPE: "cpe:/a:openbsd:openssh:8.9p1"},
	{PortID: 25, Protocol: "tcp", ServiceName: "smtp", Product: "Postfix smtpd", Version: "3.5.8", CPE: "cpe:/a:postfix:postfix:3.5.8"},
	{PortID: 53, Protocol: "udp", ServiceName: "domain", Product: "ISC BIND", Version: "9.11.3", CPE: "cpe:/a:isc:bind:9.11.3"},
	{PortID: 80, Protocol: "tcp", ServiceName: "http", Product: "nginx", Version: "1.25.0", CPE: "cpe:/a:nginx:nginx:1.25.0"},
	{PortID: 123, Protocol: "udp", ServiceName: "ntp", Product: "NTP daemon", Version: "4.2.8p15", CPE: "cpe:/a:ntp:ntp:4.2.8p15"},
	{PortID: 443, Protocol: "tcp", ServiceName: "https", Product: "Apache httpd", Version: "2.4.54", CPE: "cpe:/a:apache:http_server:2.4.54"},
	{PortID: 3306, Protocol: "tcp", ServiceName: "mysql", Product: "MySQL", Version: "8.0.29", CPE: "cpe:/a:oracle:mysql:8.0.29"},
	{PortID: 5432, Protocol: "tcp", ServiceName: "postgresql", Product: "PostgreSQL", Version: "15.2", CPE: "cpe:/a:postgresql:postgresql:15.2"},
	{PortID: 8080, Protocol: "tcp", ServiceName: "http-proxy", Product: "Apache Tomcat", Version: "9.0.65", CPE: "cpe:/a:apache:tomcat:9.0.65"},
}

func generatePortsData(size int, fromDate time.Time) []tools.PortData {
	ports := make([]tools.PortData, size)
	half := size / 2
	for i := 0; i < half; i++ {
		gofakeit.ShuffleAnySlice(predefinedServiceProfiles)
		selectedService := predefinedServiceProfiles[gofakeit.IntRange(0, len(predefinedServiceProfiles)-1)]
		ports[i] = tools.PortData{
			ID:       selectedService.PortID,
			Protocol: selectedService.Protocol,
			State:    gofakeit.RandomString([]string{"open", "filtered", "closed"}),
			Service: tools.Service{
				Name:       selectedService.ServiceName,
				Version:    selectedService.Version,
				Confidence: gofakeit.Number(1, 100),
				CPE:        selectedService.CPE,
			},
			Product:         selectedService.Product,
			Vulnerabilities: generateVuln(gofakeit.IntRange(0, 10), fromDate), // Updated signature
		}
	}
	for i := half; i < size; i++ {
		gofakeit.ShuffleAnySlice(predefinedServiceProfiles)
		selectedService := predefinedServiceProfiles[gofakeit.IntRange(0, len(predefinedServiceProfiles)-1)]

		ports[i] = tools.PortData{
			ID:       selectedService.PortID,
			Protocol: selectedService.Protocol,
			State:    gofakeit.RandomString([]string{"open", "filtered", "closed"}),
			Service: tools.Service{
				Name:       selectedService.ServiceName,
				Version:    selectedService.Version,
				Confidence: gofakeit.Number(1, 100),
				CPE:        selectedService.CPE,
			},
			Product:         selectedService.Product,
			Vulnerabilities: generateVuln(gofakeit.IntRange(0, 10), fromDate), // Updated signature
		}
	}
	return ports
}
