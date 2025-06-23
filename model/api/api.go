package api

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
