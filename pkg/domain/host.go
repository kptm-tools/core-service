package domain

import (
	"log"
	"net"
	"net/url"
	"regexp"
	"time"
)

type HostType string

const (
	Domain HostType = "domain"
	IP     HostType = "ip"
)

type Host struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	OperatorID string    `json:"user_id"`
	Name       string    `json:"name"`
	Value      string    `json:"host_value"`
	Type       HostType  `json:"host_type"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func NewHost(value string, hostType HostType, tenantID string, operatorID string, name string) *Host {
	return &Host{
		TenantID:   tenantID,
		OperatorID: operatorID,
		Name:       name,
		Value:      value,
		Type:       hostType,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
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

func ParseHostType(value string) HostType {
	if IsValidIP(value) {
		return IP
	} else {
		return Domain
	}
}
