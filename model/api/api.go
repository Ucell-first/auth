package api

import "auth/model/storage"

type Tokens struct {
	RefreshToken string `json:"refresh_token,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
}

type RegisterUserReq struct {
	Name        string `json:"name" example:"Ali"`
	Surname     string `json:"surname" example:"Valiyev"`
	Email       string `json:"email" example:"ali@example.com"`
	BirthDate   string `json:"birth_date" example:"1999-01-01"`
	Gender      string `json:"gender" example:"male" enums:"male,female"`
	Password    string `json:"password" example:"password123"`
	PhoneNumber string `json:"phone_number,omitempty" example:"+998901234567"`
	Address     string `json:"address,omitempty" example:"Tashkent"`
}

type LoginReq struct {
	Email    string `json:"email" example:"ali@example.com"`
	Password string `json:"password" example:"password123"`
}

type ResetPassReq struct {
	Email    string `json:"email" example:"ali@example.com"`
	Password string `json:"password" example:"newPassword123"`
	Code     string `json:"code" example:"123456"`
}

type ChangePasswordReq struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type UserListResponse struct {
	Users []*storage.UserInfo `json:"users"`
	Total int64               `json:"total"`
	Page  int64               `json:"page"`
	Limit int64               `json:"limit"`
}

type RegisterAdminReq struct {
	Name        string `json:"name" example:"Admin"`
	Surname     string `json:"surname" example:"Adminov"`
	Email       string `json:"email" example:"admin@example.com"`
	BirthDate   string `json:"birth_date,omitempty" example:"1990-01-01"`
	Gender      string `json:"gender,omitempty" example:"male" enums:"male,female,non-binary,other"`
	Password    string `json:"password" example:"securePassword123"`
	PhoneNumber string `json:"phone_number,omitempty" example:"+998901234567"`
	Address     string `json:"address,omitempty" example:"Tashkent"`
	Role        string `json:"role" example:"admin" enums:"admin,user"`
}
