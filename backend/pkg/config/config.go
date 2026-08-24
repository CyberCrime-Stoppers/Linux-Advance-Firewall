package config

import (
	"os"
)

// Config holds all application configuration
type Config struct {
	ServerPort      string
	DatabasePath    string
	JWTSecret       string
	AuditLogPath    string
	FrontendURL     string
}

// Load reads config from environment variables
func Load() (*Config, error) {
	return &Config{
		ServerPort:   getEnv("SERVER_PORT", "8080"),
		DatabasePath: getEnv("DATABASE_PATH", "./rules.db"),
		JWTSecret:    getEnv("JWT_SECRET", "change-me-in-production"),
		AuditLogPath: getEnv("AUDIT_LOG_PATH", "./audit.log"),
		FrontendURL:  getEnv("FRONTEND_URL", "http://localhost:5173"),
	}, nil
}

func getEnv(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}
