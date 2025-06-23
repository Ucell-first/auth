package handler

import (
	"auth/email"
	pb "auth/model/api"
	"auth/model/storage"
	"auth/tokens"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

// Register godoc
// @Summary register user
// @Description register new user
// @Tags auth
// @Accept json
// @Produce json
// @Param info body api.RegisterUserReq true "Foydalanuvchi ma'lumotlari"
// @Success 201 {object} api.Tokens "Muvaffaqiyatli ro'yxatdan o'tish"
// @Failure 400 {object} map[string]string "Noto'g'ri so'rov formati"
// @Failure 401 {object} map[string]string "Email yoki parol noto'g'ri"
// @Failure 409 {object} map[string]string "Email allaqachon mavjud"
// @Failure 500 {object} map[string]string "Server ichki xatosi"
// @Router /auth/register [post]
func (h Handler) Register(c *gin.Context) {
	h.Log.Info("Register is starting")
	req := pb.RegisterUserReq{}
	if err := c.BindJSON(&req); err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Noto'g'ri so'rov formati"})
		return
	}

	if !email.IsValidEmail(req.Email) {
		h.Log.Error("Invalid email")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Noto'g'ri email formati"})
		return
	}

	res, err := h.Cruds.User().CreateUser(c, &storage.RegisterUserReq{
		Name:        req.Name,
		Surname:     req.Surname,
		Email:       req.Email,
		BirthDate:   req.BirthDate,
		Gender:      req.Gender,
		Password:    req.Password,
		PhoneNumber: req.PhoneNumber,
		Address:     req.Address,
		Provider:    "any",
	})

	if err != nil {
		h.Log.Error(err.Error())
		status := http.StatusInternalServerError
		message := "Server ichki xatosi"

		if err.Error() == "email already exists" {
			status = http.StatusConflict
			message = "Email allaqachon mavjud"
		} else if err.Error() == "invalid credentials" {
			status = http.StatusUnauthorized
			message = "Email yoki parol noto'g'ri"
		}

		c.JSON(status, gin.H{"error": message})
		return
	}

	access, err := tokens.GenerateACCESJWTToken(res.ID, res.Role)
	if err != nil {
		h.Log.Error(fmt.Sprintf("error on generating access token: %v", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token generatsiya qilishda xato"})
		return
	}

	refresh, err := tokens.GenerateRefreshJWTToken(res.ID, res.Role)
	if err != nil {
		h.Log.Error(fmt.Sprintf("error on generating refresh token: %v", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token generatsiya qilishda xato"})
		return
	}

	if err := h.Cruds.Token().CreateToken(c, refresh, res.ID); err != nil {
		h.Log.Error("Failed to create refresh token", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	if err := h.Cruds.Token().CreateAccessToken(c, access, refresh); err != nil {
		h.Log.Error("Failed to create access token", "error", err)
		if delErr := h.Cruds.Token().DeleteToken(c, refresh); delErr != nil {
			h.Log.Error("Failed to clean up refresh token after access token creation failure", "error", delErr)
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	h.Log.Info("Register ended")
	c.JSON(http.StatusCreated, &pb.Tokens{
		RefreshToken: refresh,
		AccessToken:  access,
	})
}

// Login godoc
// @Summary login user
// @Description it generates new access and refresh tokens
// @Tags auth
// @Param userinfo body api.LoginReq true "username and password"
// @Success 200 {object} api.Tokens "Tokenlar"
// @Failure 400 {object} map[string]string "Noto'g'ri so'rov"
// @Failure 401 {object} map[string]string "Kirish rad etildi"
// @Failure 500 {object} map[string]string "Server xatosi"
// @Router /auth/login [post]
func (h Handler) Login(c *gin.Context) {
	h.Log.Info("Login jarayoni boshlandi")
	req := pb.LoginReq{}

	if err := c.BindJSON(&req); err != nil {
		h.Log.Error("Noto'g'ri so'rov formati: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Noto'g'ri so'rov formati"})
		return
	}

	res, err := h.Cruds.User().Login(c, req.Email, req.Password)
	if err != nil {
		h.Log.Error("Login jarayonida xato: " + err.Error())

		// Maxsus xatolarni tekshirish
		if err.Error() == "user not found" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Email yoki parol noto'g'ri"})
			return
		}
		if err.Error() == "invalid password" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Email yoki parol noto'g'ri"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server ichki xatosi"})
		return
	}

	access, err := tokens.GenerateACCESJWTToken(res.ID, res.Role)
	if err != nil {
		h.Log.Error("Access token generatsiya qilishda xato: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token generatsiya qilishda xato"})
		return
	}

	refresh, err := tokens.GenerateRefreshJWTToken(res.ID, res.Role)
	if err != nil {
		h.Log.Error("Refresh token generatsiya qilishda xato: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token generatsiya qilishda xato"})
		return
	}

	if err := h.Cruds.Token().CreateToken(c, refresh, res.ID); err != nil {
		h.Log.Error("Failed to create refresh token", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	if err := h.Cruds.Token().CreateAccessToken(c, access, refresh); err != nil {
		h.Log.Error("Failed to create access token", "error", err)

		if delErr := h.Cruds.Token().DeleteToken(c, refresh); delErr != nil {
			h.Log.Error("Failed to clean up refresh token after access token creation failure", "error", delErr)
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	// ... keyingi kod ...

	h.Log.Info("Muvaffaqiyatli login: " + res.Email)
	c.JSON(http.StatusOK, &pb.Tokens{
		RefreshToken: refresh,
		AccessToken:  access,
	})
}

// GetUserById godoc
// @Summary Get User By Id
// @Description Get User By Id
// @Tags auth
// @Param id path string true "USER ID"
// @Success 200 {object} storage.UserInfo
// @Failure 400 {object} map[string]string "Invalid user ID"
// @Failure 404 {object} map[string]string "User not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /auth/user/{id} [get]
func (h Handler) GetUserById(c *gin.Context) {
	h.Log.Info("GetUserById started")
	id := c.Param("id")

	if !isValidUUID(id) {
		h.Log.Error("Invalid UUID format: " + id)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	res, err := h.Cruds.User().GetUserById(c, id)
	if err != nil {
		h.Log.Error("Database error: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if res == nil {
		h.Log.Info("User not found with ID: " + id)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	h.Log.Info("GetUserById succeeded for user: " + res.Email)
	c.JSON(http.StatusOK, res)
}

func isValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}

// ForgotPassword godoc
// @Summary Forgot Password
// @Description Send password reset code to user's email
// @Tags auth
// @Param email path string true "USER email"
// @Success 200 {object} map[string]string "message"
// @Failure 400 {object} map[string]string "Invalid email format"
// @Failure 404 {object} map[string]string "Email not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /auth/forgot-password/{email} [post]
func (h Handler) ForgotPassword(c *gin.Context) {
	h.Log.Info("ForgotPassword started")
	emailreq := c.Param("email")

	if !email.IsValidEmail(emailreq) {
		h.Log.Error("Invalid email format: " + emailreq)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	user, err := h.Cruds.User().GetUserByEmail(c, emailreq)
	if err != nil {
		h.Log.Error("Database error: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if user == nil {
		h.Log.Info("Email not found: " + emailreq)
		c.JSON(http.StatusNotFound, gin.H{"error": "Email not found"})
		return
	}

	res, err := email.EmailCode(emailreq)
	if err != nil {
		h.Log.Error("Email sending error: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error sending email"})
		return
	}

	err = h.Cruds.Redis().StoreCodes(c, res, emailreq)
	if err != nil {
		h.Log.Error("Redis error: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	h.Log.Info("Password reset code sent to: " + emailreq)
	c.JSON(http.StatusOK, gin.H{"message": "Password reset code sent to your email"})
}

// ResetPassword godoc
// @Summary Reset Password
// @Description Reset user password with verification code
// @Tags auth
// @Param request body api.ResetPassReq true "Reset Password Request"
// @Success 200 {object} map[string]string "message"
// @Failure 400 {object} map[string]string "Invalid request"
// @Failure 401 {object} map[string]string "Invalid or expired code"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /auth/reset-password [post]
func (h *Handler) ResetPassword(c *gin.Context) {
	h.Log.Info("ResetPassword started")
	var req pb.ResetPassReq

	if err := c.BindJSON(&req); err != nil {
		h.Log.Error("Invalid request format: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	if len(req.Password) < 8 {
		h.Log.Error("Password too short")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters"})
		return
	}

	code, err := h.Cruds.Redis().GetCodes(c, req.Email)
	if err != nil {
		h.Log.Error("Redis error: " + err.Error())

		if err == redis.Nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired code"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		}
		return
	}

	if code != req.Code {
		h.Log.Error("Invalid code provided for email: " + req.Email)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid code"})
		return
	}

	// Kod to'g'ri ekanligi aniqlandi, parolni yangilash
	err = h.Cruds.User().UpdatePassword(c, req.Email, req.Password)
	if err != nil {
		h.Log.Error("Password update error: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	h.Log.Info("Password reset successful for: " + req.Email)
	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

// GetUserProfile godoc
// @Summary Get user profile
// @Description Get the profile of the authenticated user
// @Tags user
// @Security ApiKeyAuth
// @Success 200 {object} storage.UserInfo
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 404 {object} map[string]string "User not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /user/profile [get]
func (h *Handler) GetUserProfile(c *gin.Context) {
	h.Log.Info("GetUserProfile started")

	// Token'dan user ID ni olish
	token := c.GetHeader("Authorization")
	userID, _, err := tokens.GetUserInfoFromACCESToken(token)
	if err != nil {
		h.Log.Error("Unauthorized: " + err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	user, err := h.Cruds.User().GetUserById(c, userID)
	if err != nil {
		h.Log.Error("Database error: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if user == nil {
		h.Log.Info("User not found with ID: " + userID)
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// Parol hashini yashirish
	user.PasswordHash = ""

	h.Log.Info("GetUserProfile succeeded for user: " + user.Email)
	c.JSON(http.StatusOK, user)
}

// UpdateUserProfile godoc
// @Summary Update user profile
// @Description Update the profile of the authenticated user (does not update password)
// @Tags user
// @Security ApiKeyAuth
// @Param user body storage.UserInfo true "User data"
// @Success 200 {object} storage.UserInfo
// @Failure 400 {object} map[string]string "Invalid request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /user/profile [put]
func (h *Handler) UpdateUserProfile(c *gin.Context) {
	h.Log.Info("UpdateUserProfile started")

	// Token'dan user ID ni olish
	token := c.GetHeader("Authorization")
	userID, _, err := tokens.GetUserInfoFromACCESToken(token)
	if err != nil {
		h.Log.Error("Unauthorized: " + err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req storage.UserInfo
	if err := c.BindJSON(&req); err != nil {
		h.Log.Error("Invalid request format: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Token'dan olingan ID ni so'rovga o'rnatamiz
	req.ID = userID

	// Parolni yangilash bu endpoint orqali emas
	req.PasswordHash = ""

	updatedUser, err := h.Cruds.User().UpdateUser(c, &req)
	if err != nil {
		h.Log.Error("Update error: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// Parol hashini yashirish
	updatedUser.PasswordHash = ""

	h.Log.Info("UpdateUserProfile succeeded for user: " + updatedUser.Email)
	c.JSON(http.StatusOK, updatedUser)
}

// ChangePassword godoc
// @Summary Change user password
// @Description Change the password of the authenticated user
// @Tags user
// @Security ApiKeyAuth
// @Param passwords body api.ChangePasswordReq true "Old and new passwords"
// @Success 200 {object} map[string]string "message"
// @Failure 400 {object} map[string]string "Invalid request"
// @Failure 401 {object} map[string]string "Unauthorized or old password incorrect"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /user/password [put]
func (h *Handler) ChangePassword(c *gin.Context) {
	h.Log.Info("ChangePassword started")

	// Token'dan user ID ni olish
	token := c.GetHeader("Authorization")
	userID, _, err := tokens.GetUserInfoFromACCESToken(token)
	if err != nil {
		h.Log.Error("Unauthorized: " + err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req pb.ChangePasswordReq
	if err := c.BindJSON(&req); err != nil {
		h.Log.Error("Invalid request format: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Yangi parolning uzunligini tekshirish
	if len(req.NewPassword) < 8 {
		h.Log.Error("New password too short")
		c.JSON(http.StatusBadRequest, gin.H{"error": "new password must be at least 8 characters"})
		return
	}

	// Foydalanuvchini ma'lumotlar bazasidan olish
	user, err := h.Cruds.User().GetUserById(c, userID)
	if err != nil {
		h.Log.Error("Database error: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if user == nil {
		h.Log.Info("User not found with ID: " + userID)
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// Eski parolni tekshirish
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.OldPassword)); err != nil {
		h.Log.Error("Incorrect old password for user: " + userID)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "old password is incorrect"})
		return
	}

	// Yangi parolni yangilash
	if err := h.Cruds.User().UpdatePassword(c, user.Email, req.NewPassword); err != nil {
		h.Log.Error("Password update error: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update password"})
		return
	}

	h.Log.Info("Password changed for user: " + user.Email)
	c.JSON(http.StatusOK, gin.H{"message": "password changed successfully"})
}

// DeleteUserProfile godoc
// @Summary Delete user profile
// @Description Delete the profile of the authenticated user (soft delete)
// @Tags user
// @Security ApiKeyAuth
// @Success 200 {object} map[string]string "message"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /user/profile [delete]
func (h *Handler) DeleteUserProfile(c *gin.Context) {
	h.Log.Info("DeleteUserProfile started")

	// Token'dan user ID ni olish
	token := c.GetHeader("Authorization")
	userID, _, err := tokens.GetUserInfoFromACCESToken(token)
	if err != nil {
		h.Log.Error("Unauthorized: " + err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	if err := h.Cruds.User().DeleteUser(c, userID); err != nil {
		h.Log.Error("Delete error: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if err := h.Cruds.Token().DeleteAllTokensForUser(c, userID); err != nil {
		h.Log.Warn("Failed to delete user tokens", "user_id", userID, "error", err)
	}

	h.Log.Info("User profile deleted: " + userID)
	c.JSON(http.StatusOK, gin.H{"message": "user profile deleted"})
}

// RegisterAdmin godoc
// @Summary Register a new admin user
// @Description Create a new admin user (requires admin role)
// @Tags admin
// @Security ApiKeyAuth
// @Param admin body api.RegisterAdminReq true "Admin registration data"
// @Success 201 {object} storage.UserInfo
// @Failure 400 {object} map[string]string "Invalid request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 409 {object} map[string]string "Email already exists"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /admin/register [post]
func (h *Handler) RegisterAdmin(c *gin.Context) {
	h.Log.Info("RegisterAdmin started")
	var req pb.RegisterAdminReq
	if err := c.BindJSON(&req); err != nil {
		h.Log.Error("Invalid request format: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request format"})
		return
	}

	if !email.IsValidEmail(req.Email) {
		h.Log.Error("Invalid email format: " + req.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid email format"})
		return
	}

	if len(req.Password) < 8 {
		h.Log.Error("Password too short")
		c.JSON(http.StatusBadRequest, gin.H{"error": "password must be at least 8 characters"})
		return
	}

	admin, err := h.Cruds.User().CreateAdmin(c, &storage.RegisterAdminReq{
		Name:        req.Name,
		Surname:     req.Surname,
		Email:       req.Email,
		BirthDate:   req.BirthDate,
		Gender:      req.Gender,
		Password:    req.Password,
		PhoneNumber: req.PhoneNumber,
		Address:     req.Address,
		Role:        req.Role,
		Provider:    "any",
	})

	if err != nil {
		h.Log.Error("Admin creation error: " + err.Error())
		if strings.Contains(err.Error(), "unique constraint") {
			if strings.Contains(err.Error(), "email") {
				c.JSON(http.StatusConflict, gin.H{"error": "email already exists"})
				return
			}
			if strings.Contains(err.Error(), "phone_number") {
				c.JSON(http.StatusConflict, gin.H{"error": "phone number already exists"})
				return
			}
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create admin"})
		return
	}
	admin.PasswordHash = ""

	h.Log.Info("Admin created successfully: " + admin.Email)
	c.JSON(http.StatusCreated, admin)
}

// UserList godoc
// @Summary List users (admin only)
// @Description Get a list of users (requires admin role)
// @Tags admin
// @Security ApiKeyAuth
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(10)
// @Success 200 {object} api.UserListResponse
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /admin/users [get]
func (h *Handler) UserList(c *gin.Context) {
	h.Log.Info("UserList started")

	page, _ := strconv.ParseInt(c.Query("page"), 10, 64)
	if page == 0 {
		page = 1
	}
	limit, _ := strconv.ParseInt(c.Query("limit"), 10, 64)
	if limit == 0 {
		limit = 10
	}

	// Filtrlash (keyinchalik qo'shish mumkin)
	filter := storage.UserFilter{}

	users, total, err := h.Cruds.User().UserList(c, filter, page, limit)
	if err != nil {
		h.Log.Error("Database error: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// Parol hashlarini yashirish
	for _, u := range users {
		u.PasswordHash = ""
	}

	response := pb.UserListResponse{
		Users: users,
		Total: total,
		Page:  page,
		Limit: limit,
	}

	h.Log.Info(fmt.Sprintf("UserList succeeded, %d users returned", len(users)))
	c.JSON(http.StatusOK, response)
}

// Logout godoc
// @Summary Logout user
// @Description Invalidate the current session's tokens
// @Tags auth
// @Security ApiKeyAuth
// @Success 200 {object} map[string]string "message"
// @Failure 400 {object} map[string]string "Invalid request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /auth/logout [post]
func (h *Handler) Logout(c *gin.Context) {
	h.Log.Info("Logout started")

	// Access tokenni olish
	accessToken := c.GetHeader("Authorization")
	if accessToken == "" {
		h.Log.Error("Authorization header missing")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization header required"})
		return
	}

	// Access tokendan refresh tokenni olish
	refreshToken, err := h.Cruds.Token().GetRefreshTokenByAccesstoken(c, accessToken)
	if err != nil {
		h.Log.Error("Failed to get refresh token: " + err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid session"})
		return
	}

	// Refresh token va unga bog'langan access tokenlarni o'chirish
	if err := h.Cruds.Token().DeleteRefreshTokenAndRelatedAccessTokens(c, refreshToken); err != nil {
		h.Log.Error("Failed to delete tokens: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to logout"})
		return
	}

	h.Log.Info("Logout succeeded")
	c.JSON(http.StatusOK, gin.H{"message": "successfully logged out"})
}
