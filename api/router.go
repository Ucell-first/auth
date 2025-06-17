package api

import (
	"auth/api/handler"

	"github.com/gin-gonic/gin"
)

func Router(hand *handler.Handler) *gin.Engine {
	router := gin.Default()
	return router
}
