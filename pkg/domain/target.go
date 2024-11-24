package domain

import (
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
	Value     string     `json:"target_value"`
	Type      TargetType `json:"target_type"`
	UserID    string     `json:"user_id"`
	CreatedAt time.Time  `json:"created_at"`
}

func NewTarget(value string, targetType TargetType, userID string) *Target {
	return &Target{
		Value:     value,
		Type:      targetType,
		UserID:    userID,
		CreatedAt: time.Now().UTC(),
	}
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
