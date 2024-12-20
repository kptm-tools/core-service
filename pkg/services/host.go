package services

import (
	"crypto/tls"
	tld "github.com/jpillora/go-tld"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"net"
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

func (s *HostService) GetHostname(ip_port string) string {
	var timout time.Duration = 2
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	var domainname string
	conn, err := net.DialTimeout("tcp", ip_port, timout*time.Second)
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
