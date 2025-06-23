package handler

import (
	"auth/email"
	pb "auth/model/api"
	"auth/model/storage"
	"auth/tokens"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// Register godoc
// @Summary Foydalanuvchini ro'yxatdan o'tkazish
// @Description Yangi foydalanuvchi yaratish va JWT tokenlarini qaytarish
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

	refresh, err := tokens.GenerateRefreshJWTToken(res.ID, res.Role, h.Cruds)
	if err != nil {
		h.Log.Error(fmt.Sprintf("error on generating refresh token: %v", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token generatsiya qilishda xato"})
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

	refresh, err := tokens.GenerateRefreshJWTToken(res.ID, res.Role, h.Cruds)
	if err != nil {
		h.Log.Error("Refresh token generatsiya qilishda xato: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token generatsiya qilishda xato"})
		return
	}

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
