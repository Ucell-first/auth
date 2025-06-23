package main

import (
	"auth/api"
	"auth/api/handler"
	cs "auth/casbin"
	"auth/config"
	"auth/logs"
	"auth/storage"
	"auth/storage/postgres"
	"auth/storage/redisnosql"
	"context"
	"log"
	"log/slog"
	"time"

	"github.com/casbin/casbin/v2"
)

func main() {
	cfg := config.Load()
	pdbs, err := postgres.ConnectionPDb()
	if err != nil {
		log.Fatal(err)
	}
	rdbs := redisnosql.ConnectRDB()

	logger := logs.NewLogger()

	dbs := storage.NewStorage(pdbs, rdbs)
	defer func() {
		if err := dbs.ClosePDB(); err != nil {
			logger.Error("Failed to close PostgreSQL connection", "error", err)
		}
		if err := dbs.CloseRDB(); err != nil {
			logger.Error("Failed to close Redis connection", "error", err)
		}
	}()

	go startTokenCleanupScheduler(dbs, time.Hour, logger)

	casbin, err := cs.CasbinEnforcer(logger)
	if err != nil {
		log.Fatal(err)
	}

	hand := NewHandler(logger, dbs, casbin)
	router := api.Router(hand)
	err = router.Run(cfg.Server.USER_ROUTER)
	if err != nil {
		log.Fatal(err)
	}
}

func NewHandler(log *slog.Logger, st storage.IStorage, casbin *casbin.Enforcer) *handler.Handler {
	return &handler.Handler{
		Cruds:  st,
		Log:    log,
		Casbin: casbin,
	}
}

func startTokenCleanupScheduler(tokenRepo storage.IStorage, interval time.Duration, logger *slog.Logger) {
	logger.Info("Starting token cleanup scheduler", "interval", interval.String())
	cleanupTokens(context.Background(), tokenRepo, logger)

	// Har bir intervalda tozalashni takrorlash
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// for range yordamida channeldan foydalanish
	for range ticker.C {
		cleanupTokens(context.Background(), tokenRepo, logger)
	}
}

func cleanupTokens(ctx context.Context, tokenRepo storage.IStorage, logger *slog.Logger) {
	logger.Info("Starting token cleanup")
	startTime := time.Now()

	if err := tokenRepo.Token().DeleteExpiredTokens(ctx); err != nil {
		logger.Error("Token cleanup failed", "error", err)
	} else {
		duration := time.Since(startTime)
		logger.Info("Token cleanup completed",
			"duration", duration.String(),
			"duration_ms", duration.Milliseconds())
	}
}
