package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	ApplicationID          string
	AllowedOrigins         string
	FusionAuthAPIKey       string
	FusionAuthHost         string
	FusionAuthPort         string
	BlueprintTenantID      string
	BlueprintApplicationID string
	DatabaseUser           string
	DatabasePassword       string
	DatabaseName           string
	DatabaseHost           string
	DatabasePort           string
	NatsHost               string
	NatsPort               string
}

func fetchEnv(varString string, fallbackString string) string {
	env, found := os.LookupEnv(varString)

	if !found {
		return fallbackString
	}

	return env
}

func LoadConfig() *Config {
	config := &Config{
		ApplicationID:          fetchEnv("APPLICATION_ID", "e9fdb985-9173-4e01-9d73-ac2d60d1dc8e"),
		AllowedOrigins:         fetchEnv("ALLOWED_ORIGINS", "http://localhost:8000,http://localhost:5173"),
		FusionAuthAPIKey:       fetchEnv("FUSIONAUTH_API_KEY", "this_really_should_be_a_long_random_alphanumeric_value_but_this_still_works"),
		FusionAuthHost:         fetchEnv("FUSIONAUTH_HOST", "localhost"),
		FusionAuthPort:         fetchEnv("FUSIONAUTH_PORT", "9011"),
		BlueprintTenantID:      fetchEnv("FUSIONAUTH_BLUEPRINT_TENANTID", "79c9acd6-a590-4394-8f2c-fadb07b79113"),
		BlueprintApplicationID: fetchEnv("FUSIONAUTH_BLUEPRINT_APPID", "c412a5bf-2524-46e9-85a6-08d1f1777295"),
		DatabaseUser:           fetchEnv("DB_USER", "postgres"),
		DatabasePassword:       fetchEnv("DB_PASSWORD", "postgres"),
		DatabaseName:           fetchEnv("CORE_DB_NAME", "core_service_db"),
		DatabaseHost:           fetchEnv("DB_HOST", "localhost"),
		DatabasePort:           fetchEnv("DB_PORT", "5432"),
		NatsHost:               fetchEnv("NATS_HOST", "localhost"),
		NatsPort:               fetchEnv("NATS_PORT", "4222"),
	}

	return config
}

func (c *Config) PostgreSQLRootConnStr() string {
	return fmt.Sprintf(
		"host=%s user=%s dbname=%s password=%s sslmode=disable",
		c.DatabaseHost, c.DatabaseUser, "postgres", c.DatabasePassword,
	)

}

func (c *Config) PostgreSQLCoreConnStr() string {
	return fmt.Sprintf(
		"host=%s user=%s dbname=%s password=%s sslmode=disable",
		c.DatabaseHost, c.DatabaseUser, c.DatabaseName, c.DatabasePassword,
	)
}

func (c *Config) GetAllowedOrigins() []string {
	return strings.Split(c.AllowedOrigins, ",")
}

func (c *Config) GetNatsConnStr() string {
	return fmt.Sprintf("http://%s:%s", c.NatsHost, c.NatsPort)
}
