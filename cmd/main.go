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
	"log"
	"log/slog"

	"github.com/casbin/casbin/v2"
)

func main() {
	pdbs, err := postgres.ConnectionPDb()
	if err != nil {
		log.Fatal(err)
	}
	rdbs := redisnosql.ConnectRDB()

	logger := logs.NewLogger()

	dbs := storage.NewStorage(pdbs, rdbs)
	defer dbs.ClosePDB()
	defer dbs.CloseRDB()

	casbin, err := cs.CasbinEnforcer(logger)
	if err != nil {
		log.Fatal(err)
	}

	hand := NewHandler(logger, dbs, casbin)
	router := api.Router(hand)
	err = router.Run(config.Load().Server.USER_ROUTER)
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
