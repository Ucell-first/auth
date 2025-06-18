package storage

type RegisterUserReq struct {
	Name        string `json:"name" example:"Ali"`
	Surname     string `json:"surname" example:"Valiyev"`
	Email       string `json:"email" example:"ali@example.com"`
	BirthDate   string `json:"birth_date" example:"1999-01-01"`
	Gender      string `json:"gender" example:"male" enums:"male,female"`
	Password    string `json:"password,omitempty" example:"password123"`
	PhoneNumber string `json:"phone_number,omitempty" example:"+998901234567"`
	Address     string `json:"address,omitempty" example:"Tashkent"`
	Provider    string `json:"provider" example:"any" enums:"google,any"`
}

type UserInfo struct {
	ID           string `json:"id" example:"550e8400-e29b-41d4-a716-446655440000"`
	Name         string `json:"name" example:"Ali"`
	Surname      string `json:"surname" example:"Valiyev"`
	Email        string `json:"email" example:"ali@example.com"`
	BirthDate    string `json:"birth_date" example:"1999-01-01"`
	Gender       string `json:"gender" example:"male" enums:"male,female"`
	PasswordHash string `json:"password_hash,omitempty" example:"password123"`
	PhoneNumber  string `json:"phone_number,omitempty" example:"+998901234567"`
	Address      string `json:"address,omitempty" example:"Tashkent"`
	Role         string `json:"role" example:"user" enums:"admin,user"`
	Provider     string `json:"provider" example:"any" enums:"google,any"`
	CreatedAt    string `json:"created_at,omitempty"`
	UpdatedAt    string `json:"updated_at,omitempty"`
	DeletedAt    int64  `json:"deleted_at,omitempty"`
}

type RegisterAdminReq struct {
	Name        string `json:"name" example:"Ali"`
	Surname     string `json:"surname" example:"Valiyev"`
	Email       string `json:"email" example:"ali@example.com"`
	BirthDate   string `json:"birth_date" example:"1999-01-01"`
	Gender      string `json:"gender" example:"male" enums:"male,female"`
	Password    string `json:"password,omitempty" example:"password123"`
	PhoneNumber string `json:"phone_number,omitempty" example:"+998901234567"`
	Address     string `json:"address,omitempty" example:"Tashkent"`
	Role        string `json:"role" example:"admin" enums:"admin,user"`
	Provider    string `json:"provider" example:"any" enums:"google,any"`
}

type UserFilter struct {
	Name     *string
	Surname  *string
	Email    *string
	Gender   *string
	Role     *string
	Provider *string
	Phone    *string
	Address  *string
}
