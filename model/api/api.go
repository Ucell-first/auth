package api

type Tokens struct {
	RefreshToken string `json:"refresh_token"`
	AccesToken   string `json:"acces_token"`
}

type RegisterUserReq struct {
	Name        string `json:"name" example:"Ali"`
	Surname     string `json:"surname" example:"Valiyev"`
	Email       string `json:"email" example:"ali@example.com"`
	BirthDate   string `json:"birth_date" example:"1999-01-01"`
	Gender      string `json:"gender" example:"male" enums:"male,female"`
	Password    string `json:"password,omitempty" example:"password123"`
	PhoneNumber string `json:"phone_number,omitempty" example:"+998901234567"`
	Address     string `json:"address,omitempty" example:"Tashkent"`
}
