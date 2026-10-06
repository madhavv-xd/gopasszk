package config

import (
	"fmt"
	"github.com/joho/godotenv"
	"os"
	"path/filepath"
	"errors"
)

type Config struct {
	DBUser     string
	DBPassword string
	DBName     string
	DBHost     string
	ServerSecret string
	JWTSecret string
	DBPort string 
	DBSSLMode string 
}

func findEnvFile() string {
	dir, _ := os.Getwd()
	for {
		envPath := filepath.Join(dir, ".env")
		if _, err := os.Stat(envPath); err == nil {
			return envPath
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ".env"
		}
		dir = parent
	}
}

func getEnv(key , fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v //return the value
	}
	//else fallback
	return fallback
}

func LoadConfig() (*Config, error) {
	if err := godotenv.Load(findEnvFile()); err != nil {
		fmt.Println("Warning: no .env file found:", err)
	}

	cfg := &Config{
		DBUser:       os.Getenv("POSTGRES_USER"),
		DBPassword:   os.Getenv("POSTGRES_PASSWORD"),
		DBName:       os.Getenv("POSTGRES_DB"),
		ServerSecret: os.Getenv("SALT_HMAC_SECRET"),
		JWTSecret:    os.Getenv("JWT_SECRET"),
		DBHost:       getEnv("DB_HOST", "localhost"),
		DBPort:       getEnv("DB_PORT", "5432"),
		DBSSLMode:    getEnv("DB_SSLMODE", "disable"),
	}

	if cfg.DBUser == "" {
		return nil, errors.New("POSTGRES_USER is not set")
	}
	if cfg.DBPassword == "" {
		return nil, errors.New("POSTGRES_PASSWORD is not set")
	}
	if cfg.DBName == "" {
		return nil, errors.New("POSTGRES_DB is not set")
	}
	if cfg.ServerSecret == "" {
		return nil, errors.New("SALT_HMAC_SECRET is not set")
	}
	if cfg.JWTSecret == "" {
		return nil, errors.New("JWT_SECRET is not set")
	}

	return cfg, nil
}
