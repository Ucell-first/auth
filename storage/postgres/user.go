package postgres

import (
	pb "auth/model/storage"
	"auth/storage"
	"context"
	"database/sql"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type UserRepository struct {
	Db *sql.DB
}

func NewUserRepository(db *sql.DB) storage.IUserStorage {
	return &UserRepository{Db: db}
}

func (u UserRepository) CreateUser(ctx context.Context, req *pb.RegisterUserReq) (*pb.UserInfo, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	var birthDate sql.NullTime
	if req.BirthDate != "" {
		t, err := time.Parse("2006-01-02", req.BirthDate)
		if err != nil {
			return nil, fmt.Errorf("invalid birth_date format: %w", err)
		}
		birthDate = sql.NullTime{Time: t, Valid: true}
	} else {
		birthDate = sql.NullTime{Valid: false}
	}

	query := `
	INSERT INTO users (
		name, 
		surname, 
		email, 
		birth_date, 
		gender, 
		password_hash, 
		phone_number, 
		address,
		provider
	)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	RETURNING 
		id, 
		name, 
		surname, 
		email, 
		birth_date, 
		gender, 
		phone_number, 
		address, 
		role, 
		provider,
		created_at,
		updated_at,
		deleted_at`

	var user pb.UserInfo
	var dbBirthDate time.Time

	err = u.Db.QueryRowContext(ctx, query,
		req.Name,
		req.Surname,
		req.Email,
		birthDate,
		req.Gender,
		string(hashedPassword),
		sql.NullString{String: req.PhoneNumber, Valid: req.PhoneNumber != ""},
		sql.NullString{String: req.Address, Valid: req.Address != ""},
		req.Provider,
	).Scan(
		&user.ID,
		&user.Name,
		&user.Surname,
		&user.Email,
		&dbBirthDate,
		&user.Gender,
		&user.PhoneNumber,
		&user.Address,
		&user.Role,
		&user.Provider,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.DeletedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to insert user: %w", err)
	}

	if birthDate.Valid {
		user.BirthDate = birthDate.Time.Format("2006-01-02")
	} else {
		user.BirthDate = ""
	}
	user.PasswordHash = ""

	return &user, nil
}

func (u UserRepository) CreateAdmin(ctx context.Context, req *pb.RegisterAdminReq) (*pb.UserInfo, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	var birthDate sql.NullTime
	if req.BirthDate != "" {
		t, err := time.Parse("2006-01-02", req.BirthDate)
		if err != nil {
			return nil, fmt.Errorf("invalid birth_date format: %w", err)
		}
		birthDate = sql.NullTime{Time: t, Valid: true}
	} else {
		birthDate = sql.NullTime{Valid: false}
	}

	query := `
	INSERT INTO users (
		name, 
		surname, 
		email, 
		birth_date, 
		gender, 
		password_hash, 
		phone_number, 
		address,
		role,
		provider
	)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	RETURNING 
		id, 
		name, 
		surname, 
		email, 
		birth_date, 
		gender, 
		phone_number, 
		address, 
		role, 
		provider,
		created_at,
		updated_at,
		deleted_at`

	var user pb.UserInfo
	var dbBirthDate time.Time

	err = u.Db.QueryRowContext(ctx, query,
		req.Name,
		req.Surname,
		req.Email,
		birthDate,
		req.Gender,
		string(hashedPassword),
		sql.NullString{String: req.PhoneNumber, Valid: req.PhoneNumber != ""},
		sql.NullString{String: req.Address, Valid: req.Address != ""},
		req.Role,
		req.Provider,
	).Scan(
		&user.ID,
		&user.Name,
		&user.Surname,
		&user.Email,
		&dbBirthDate,
		&user.Gender,
		&user.PhoneNumber,
		&user.Address,
		&user.Role,
		&user.Provider,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.DeletedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to insert admin: %w", err)
	}

	if birthDate.Valid {
		user.BirthDate = birthDate.Time.Format("2006-01-02")
	} else {
		user.BirthDate = ""
	}

	user.PasswordHash = ""

	return &user, nil
}
