package api

import (
	_ "auth/api/docs"
	"auth/api/handler"
	"auth/api/middleware"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
// @title User
// @version 1.0
// @description API Gateway
// BasePath: /
func Router(hand *handler.Handler) *gin.Engine {
	router := gin.Default()
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	authGroup := router.Group("/auth")
	{
		authGroup.POST("/register", hand.Register)
		authGroup.POST("/login", hand.Login)
		authGroup.GET("/user/:id", hand.GetUserById)
		authGroup.POST("/forgot-password/:email", hand.ForgotPassword)
		authGroup.POST("/reset-password", hand.ResetPassword)
		authGroup.POST("/logout", middleware.Check(hand.Cruds), hand.Logout)
	}

	userGroup := router.Group("/user")
	userGroup.Use(middleware.Check(hand.Cruds))
	{
		userGroup.GET("/profile", hand.GetUserProfile)
		userGroup.PUT("/profile", hand.UpdateUserProfile)
		userGroup.PUT("/password", hand.ChangePassword)
		userGroup.DELETE("/profile", hand.DeleteUserProfile)
	}

	adminGroup := router.Group("/admin")
	adminGroup.Use(middleware.Check(hand.Cruds))
	adminGroup.Use(middleware.CheckPermissionMiddleware(hand.Casbin))
	{
		adminGroup.POST("/register", hand.RegisterAdmin)
		adminGroup.GET("/users", hand.UserList)
	}
	return router
}
