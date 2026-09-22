package config

import (
	"fmt"
	"github.com/joho/godotenv"
	"os"
	"path/filepath"
)

type Config struct {
	DBUser     string
	DBPassword string
	DBName     string
	DBHost     string
	ServerSecret string
	JWTSecret string
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

func LoadConfig() *Config {
	err := godotenv.Load(findEnvFile())
	if err != nil {
		fmt.Println("Warning: no .env file found:", err)
	}
	return &Config{
		DBUser:     os.Getenv("POSTGRES_USER"),
		DBPassword: os.Getenv("POSTGRES_PASSWORD"),
		DBName:     os.Getenv("POSTGRES_DB"),
		DBHost:     "localhost",
		ServerSecret: os.Getenv("SALT_HMAC_SECRET"),
		JWTSecret: os.Getenv("JWT_SECRET"),
	}
}
