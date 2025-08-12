package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/joho/godotenv"
)

type Config struct {
	Server struct {
		Host           string
		Port           string
		AllowedOrigins string
	}

	FusionAuth struct {
		APIKey                 string
		Host                   string
		Port                   string
		BlueprintTenantID      string
		BlueprintApplicationID string
		ApplicationID          string
	}

	Database struct {
		User     string
		Password string
		Name     string
		Host     string
		Port     string
	}

	Nats struct {
		Host        string
		Port        string
		MonitorPort string
	}

	SMTP struct {
		Host      string
		Port      string
		Username  string
		Password  string
		FromEmail string
	}

	Websocket struct {
		IntervalScanRefresh string
	}
	Workers struct {
		Size string
	}
}

var (
	configInstance *Config
	loadConfigOnce sync.Once
)

func LoadConfig() *Config {
	loadConfigOnce.Do(func() {
		configInstance = load() // Call the actual loading logic once
	})
	return configInstance
}

func load() *Config {
	if os.Getenv("GO_ENV") != "production" {
		err := godotenv.Load()
		if err != nil {
			slog.Warn("No .env file found, using system environment variables")
		}
	}

	cfg := &Config{}

	cfg.Server = struct {
		Host           string
		Port           string
		AllowedOrigins string
	}{
		Host:           fetchEnv("SERVER_HOST", "localhost"),
		Port:           fetchEnv("SERVER_PORT", "8000"),
		AllowedOrigins: fetchEnv("ALLOWED_ORIGINS", "http://localhost:8000,http://localhost:5173"),
	}

	cfg.FusionAuth = struct {
		APIKey                 string
		Host                   string
		Port                   string
		BlueprintTenantID      string
		BlueprintApplicationID string
		ApplicationID          string
	}{
		ApplicationID:          fetchEnv("APPLICATION_ID", "e9fdb985-9173-4e01-9d73-ac2d60d1dc8e"),
		APIKey:                 fetchEnvOrPanic("FUSIONAUTH_API_KEY"),
		Host:                   fetchEnv("FUSIONAUTH_HOST", "localhost"),
		Port:                   fetchEnv("FUSIONAUTH_PORT", "9011"),
		BlueprintTenantID:      fetchEnv("FUSIONAUTH_BLUEPRINT_TENANTID", "79c9acd6-a590-4394-8f2c-fadb07b79113"),
		BlueprintApplicationID: fetchEnv("FUSIONAUTH_BLUEPRINT_APPID", "c412a5bf-2524-46e9-85a6-08d1f1777295"),
	}

	cfg.Database = struct {
		User     string
		Password string
		Name     string
		Host     string
		Port     string
	}{
		User:     fetchEnvOrPanic("DB_USER"),
		Password: fetchEnvOrPanic("DB_PASSWORD"),
		Name:     fetchEnvOrPanic("DB_NAME"),
		Host:     fetchEnv("DB_HOST", "localhost"),
		Port:     fetchEnv("DB_PORT", "5432"),
	}

	cfg.Nats = struct {
		Host        string
		Port        string
		MonitorPort string
	}{
		Host:        fetchEnv("NATS_HOST", "localhost"),
		Port:        fetchEnv("NATS_PORT", "4222"),
		MonitorPort: fetchEnv("NATS_MONITOR_PORT", "8222"),
	}

	cfg.SMTP = struct {
		Host      string
		Port      string
		Username  string
		Password  string
		FromEmail string
	}{
		Host:      fetchEnvOrPanic("SMTP_HOST"),
		Port:      fetchEnvOrPanic("SMTP_PORT"),
		Username:  fetchEnvOrPanic("SMTP_USER"),
		FromEmail: fetchEnvOrPanic("SMTP_FROM_EMAIL"),
		Password:  fetchEnvOrPanic("SMTP_PASS"),
	}
	cfg.Websocket = struct{ IntervalScanRefresh string }{IntervalScanRefresh: fetchEnv("WS_SCAN_INTERVAL_NOTIFICATION", "60")}
	cfg.Workers = struct{ Size string }{Size: fetchEnv("WORKERS_SIZE", "2")}
	return cfg
}

func fetchEnv(varString string, fallbackString string) string {
	value, found := os.LookupEnv(varString)

	if !found {
		return fallbackString
	}

	return value
}

func fetchEnvOrPanic(key string) string {
	value, found := os.LookupEnv(key)
	if !found || value == "" {
		if isTestEnv() {
			return "test-default-value"
		}
		panic(fmt.Sprintf("missing required environment variable: %s", key))
	}
	return value
}

func (c *Config) PostgreSQLCoreConnStr() string {
	return fmt.Sprintf(
		"host=%s user=%s dbname=%s password=%s sslmode=disable",
		c.Database.Host, c.Database.User, c.Database.Name, c.Database.Password,
	)
}

func (c *Config) PostgreSQLDefaultDatabaseURL() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%s/postgres?sslmode=disable",
		c.Database.User,
		c.Database.Password,
		c.Database.Host,
		c.Database.Port,
	)
}

func (c *Config) PostgreSQLCoreDatabaseURL() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		c.Database.User,
		c.Database.Password,
		c.Database.Host,
		c.Database.Port,
		c.Database.Name,
	)
}

func (c *Config) GetAllowedOrigins() []string {
	return strings.Split(c.Server.AllowedOrigins, ",")
}

func (c *Config) GetNatsConnStr() string {
	return fmt.Sprintf("http://%s:%s", c.Nats.Host, c.Nats.Port)
}

func (c *Config) GetNatsHealthcheckURL() string {
	return fmt.Sprintf("http://%s:%s/healthz", c.Nats.Host, c.Nats.MonitorPort)
}

func isTestEnv() bool {
	return os.Getenv("GO_ENV") == "test" || strings.HasSuffix(os.Args[0], ".test")
}

func (c *Config) GetServerHost(hasPrefix bool) string {
	var s string
	if c.Server.Host == "localhost" {
		s = c.Server.Host + ":" + c.Server.Port
		if !hasPrefix {
			return s
		}
		return "http://" + s
	} else {
		if !hasPrefix {
			return c.Server.Host
		}
		return "https://" + s
	}
}

func (c *Config) GetScheme() []string {
	if c.Server.Host == "localhost" {
		return []string{"http"}
	}
	return []string{"https"}
}
