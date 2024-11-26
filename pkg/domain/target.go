package domain

import (
	"log"
	"net"
	"net/url"
	"regexp"
	"time"
)

type TargetType string

const (
	Domain TargetType = "domain"
	IP     TargetType = "ip"
)

type Target struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	OperatorID string     `json:"user_id"`
	Value      string     `json:"target_value"`
	Type       TargetType `json:"target_type"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

func NewTarget(value string, targetType TargetType, tenantID string, operatorID string) *Target {
	return &Target{
		TenantID:   tenantID,
		OperatorID: operatorID,
		Value:      value,
		Type:       targetType,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
}

func IsValidTargetValue(value string) bool {

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
	// Try parsing the target as an IP address
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

func ParseTargetType(value string) TargetType {
	if IsValidIP(value) {
		return IP
	} else {
		return Domain
	}
}
