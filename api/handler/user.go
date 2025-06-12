package handler

import (
	"auth/model/storage"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Register godoc
// @Summary Register user
// @Description create new users
// @Tags auth
// @Param info body storage.User true "User info"
// @Success 200 {object} string "message"
// @Failure 400 {object} string "Invalid data"
// @Failure 500 {object} string "Server error"
// @Router /auth/register [post]
func (h Handler) Register(c *gin.Context) {
	req := storage.User{}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{
		"message": req,
	})
}
