package services

import (
	"crypto/tls"
	"log"
	"net"
	"regexp"
	"strings"
	"time"

	tld "github.com/jpillora/go-tld"
	cmmn "github.com/kptm-tools/common/common/events"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	probing "github.com/prometheus-community/pro-bing"
)

type HostService struct {
	storage interfaces.IStorage
}

var _ interfaces.IHostService = (*HostService)(nil)

func NewHostService(storage interfaces.IStorage) *HostService {
	return &HostService{
		storage: storage,
	}
}

func (s *HostService) CreateHost(t *domain.Host) (*domain.Host, error) {

	return s.storage.CreateHost(t)
}

func (s *HostService) GetHostsByTenantIDAndUserID(tenantID string, userID string) ([]*domain.Host, error) {

	hosts, err := s.storage.GetHostsByTenantIDAndUserID(tenantID, userID)

	if err != nil {
		return nil, err
	}

	return hosts, nil
}

func (s *HostService) GetHostByID(ID int) (*domain.Host, error) {
	host, err := s.storage.GetHostByID(ID)

	if err != nil {
		return nil, err
	}

	return host, nil
}

func (s *HostService) DeleteHostByID(ID int) (bool, error) {
	isDeleted, err := s.storage.DeleteHostByID(ID)

	if err != nil {
		return false, err
	}

	return isDeleted, nil
}

func (s *HostService) GetHostname(ipPort string) string {
	var timout time.Duration = 2
	conf := &tls.Config{
		InsecureSkipVerify: false,
	}
	var domainname string
	conn, err := net.DialTimeout("tcp", ipPort, timout*time.Second)
	if err == nil {
		tlsconn := tls.Client(conn, conf)
		handshake := tlsconn.Handshake()
		if handshake == nil {
			state := tlsconn.ConnectionState()
			hostname := state.PeerCertificates[0].Subject.CommonName
			hostname = "https://" + hostname
			u, errr := tld.Parse(hostname)
			if errr == nil {
				if u.Subdomain == "*" || u.Subdomain == "" {
					domainname = u.Domain + "." + u.TLD
				} else {
					domainname = u.Subdomain + "." + u.Domain + "." + u.TLD
				}
			}
			tlsconn.Close()
		}
		conn.Close()
	}

	return domainname
}

func (s *HostService) PatchHostByID(h *domain.Host) (*domain.Host, error) {
	host, err := s.storage.PatchHostByID(h)

	if err != nil {
		return nil, err
	}

	return host, nil
}

func (s *HostService) ValidateHost(host string) (string, error) {

	if IsValidHostValue(host) {
		normalizedHost := cmmn.NormalizeURL(host)
		addr := strings.Split(normalizedHost, "//")[1]
		pinger, err := probing.NewPinger(addr)
		if err != nil {
			log.Printf("failed to probe host: %v", err)
			return "Unable to connect host", nil
		}
		pinger.Count = 1
		pinger.Timeout = 5 * time.Second
		err = pinger.Run()
		defer pinger.Stop()
		if err != nil {
			return "", err
		}

		stats := pinger.Statistics()
		log.Println(stats)
		return "Verified", nil
	} else {
		return "Invalid value", nil
	}
}

func IsValidHostValue(value string) bool {

	normalizedValue := cmmn.NormalizeURL(value)
	if cmmn.IsURL(normalizedValue) {
		domain, err := cmmn.ExtractDomain(normalizedValue)
		if err != nil {
			log.Println("Invalid URL/Domain: ", normalizedValue)
			return false
		}

		// Domain with protocol prefix
		if IsValidDomain(domain) {
			return true
		}

		// IP address with protocol prefix
		if cmmn.IsValidIPv4(strings.Split(normalizedValue, "//")[1]) {
			return true
		}
	}

	// IP address on its own
	if cmmn.IsValidIPv4(value) {
		return true
	}

	log.Println("Invalid IP:", value)
	return false

}

func IsValidDomain(domain string) bool {
	re := regexp.MustCompile(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)
	return re.MatchString(domain)
}

func (s *HostService) ValidateAlias(alias string) (string, error) {
	exists, err := s.storage.ExistAlias(alias)
	if err != nil {
		return "", err
	}
	if exists {
		return "Exist", nil
	}
	return "Not Exist", nil
}
