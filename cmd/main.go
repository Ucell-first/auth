package main

import (
	"auth/api"
	"auth/api/handler"
	"auth/config"
	"database/sql"
	"log"
)

var Db *sql.DB

func main() {
	hand := NewHandler()
	router := api.Router(hand)
	err := router.Run(config.Load().Server.USER_ROUTER)
	if err != nil {
		log.Fatal(err)
	}
}

func NewHandler() *handler.Handler {
	return &handler.Handler{}
}
