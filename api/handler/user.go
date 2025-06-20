package handler

import (
	"auth/email"
	pb "auth/model/api"
	"auth/model/storage"
	"auth/tokens"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
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

		// Xatolik turini aniqlash
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

	h.Log.Info("Register ended")
	c.JSON(http.StatusCreated, &pb.Tokens{RefreshToken: refresh, AccesToken: access})
}
