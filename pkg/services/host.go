package services

import (
	"crypto/tls"
	tld "github.com/jpillora/go-tld"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	probing "github.com/prometheus-community/pro-bing"
	"log"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
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

func (s *HostService) GetHostByID(ID string) (*domain.Host, error) {
	host, err := s.storage.GetHostByID(ID)

	if err != nil {
		return nil, err
	}

	return host, nil
}

func (s *HostService) DeleteHostByID(ID string) (bool, error) {
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

func (s *HostService) PatchHostByID(ID, domainName, ip, alias string, credential, rapporteur []byte) (*domain.Host, error) {
	host, err := s.storage.PatchHostByID(ID, domainName, ip, alias, credential, rapporteur)

	if err != nil {
		return nil, err
	}

	return host, nil
}

func (s *HostService) ValidateHost(host string) (string, error) {
	if IsValidHostValue(host) {

		pinger, err := probing.NewPinger(strings.Split(host, "//")[1])
		if err != nil {
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

	if IsValidURL(value) {
		domain, err := ExtractDomainFromURL(value)

		if err != nil {
			log.Println("Invalid URL/Domain")
			return false
		}

		if IsValidDomain(domain) {
			return true
		}
	}

	if IsValidIP(value) {
		return true
	}

	log.Println("Invalid IP")
	return false

}

func IsValidIP(value string) bool {
	// Try parsing the host as an IP address
	return net.ParseIP(value) != nil
}

func IsValidURL(url string) bool {
	re := regexp.MustCompile(`^(http|https)://[a-zA-Z0-9-]+\.[a-zA-Z]{2,}.*$`)
	return re.MatchString(url)
}

func ExtractDomainFromURL(input string) (string, error) {
	parsedURL, err := url.Parse(input)
	if err != nil {
		return "", err
	}

	return parsedURL.Hostname(), nil

}

func IsValidDomain(domain string) bool {
	re := regexp.MustCompile(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)
	return re.MatchString(domain)
}
