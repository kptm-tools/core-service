package config

import (
	"fmt"
	"os"
)

type Config struct {
	DatabaseUser     string
	DatabasePassword string
	DatabaseName     string
	DatabaseHost     string
	DatabasePort     string
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
		DatabaseUser:     fetchEnv("DB_USER", "postgres"),
		DatabasePassword: fetchEnv("DB_PASSWORD", "mysecretpassword"),
		DatabaseName:     fetchEnv("DB_NAME", "kriptome"),
		DatabaseHost:     fetchEnv("DB_HOST", "localhost"),
		DatabasePort:     fetchEnv("DB_PORT", "5432"),
	}

	return config
}

func (c *Config) PostgreSQLConnStr() string {
	return fmt.Sprintf(
		"host=%s user=%s dbname=%s password=%s sslmode=disable",
		c.DatabaseHost, c.DatabaseUser, c.DatabaseName, c.DatabasePassword,
	)

}
