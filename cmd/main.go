package main

import (
	"auth/api"
	"auth/api/handler"
	"auth/config"
	"log"
)

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
