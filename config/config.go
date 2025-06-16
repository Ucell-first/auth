package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/spf13/cast"
)

type Config struct {
	Postgres PostgresConfig
	Server   ServerConfig
	Token    TokensConfig
	Redis    RedisConfig
	Email    EmailConfig
}

type PostgresConfig struct {
	PDB_NAME     string
	PDB_PORT     string
	PDB_PASSWORD string
	PDB_USER     string
	PDB_HOST     string
}

type RedisConfig struct {
	RDB_ADDRESS  string
	RDB_PASSWORD string
}

type ServerConfig struct {
	USER_ROUTER string
}

type TokensConfig struct {
	ACCES_TOKEN_KEY   string
	REFRESH_TOKEN_KEY string
}

type EmailConfig struct {
	SENDER_EMAIL string
	APP_PASSWORD string
}

func Load() *Config {
	if err := godotenv.Load(".env"); err != nil {
		log.Printf("error while loading .env file: %v", err)
	}

	return &Config{
		Postgres: PostgresConfig{
			PDB_HOST:     cast.ToString(coalesce("PDB_HOST", "localhost")),
			PDB_PORT:     cast.ToString(coalesce("PDB_PORT", "5432")),
			PDB_USER:     cast.ToString(coalesce("PDB_USER", "postgres")),
			PDB_NAME:     cast.ToString(coalesce("PDB_NAME", "postgres")),
			PDB_PASSWORD: cast.ToString(coalesce("PDB_PASSWORD", "3333")),
		},
		Server: ServerConfig{
			USER_ROUTER: cast.ToString(coalesce("USER_ROUTER", ":1234")),
		},
		Token: TokensConfig{
			ACCES_TOKEN_KEY:   cast.ToString(coalesce("ACCES_TOKEN_KEY", "your_secret_key1")),
			REFRESH_TOKEN_KEY: cast.ToString(coalesce("REFRESH_TOKEN_KEY", "your_secret_key2")),
		},
		Redis: RedisConfig{
			RDB_ADDRESS:  cast.ToString(coalesce("RDB_ADDRESS", "localhost:6379")),
			RDB_PASSWORD: cast.ToString(coalesce("RDB_PASSWORD", "")),
		},
		Email: EmailConfig{
			SENDER_EMAIL: cast.ToString(coalesce("SENDER_EMAIL", "your_email@example.com")),
			APP_PASSWORD: cast.ToString(coalesce("APP_PASSWORD", "your_password")),
		},
	}
}

func coalesce(key string, value interface{}) interface{} {
	val, exist := os.LookupEnv(key)
	if exist {
		return val
	}
	return value
}
