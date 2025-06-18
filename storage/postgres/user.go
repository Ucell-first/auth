package postgres

import (
	pb "auth/model/storage"
	"auth/storage/repo"
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type UserRepository struct {
	Db *sql.DB
}

func NewUserRepository(db *sql.DB) repo.IUserStorage {
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

func (u UserRepository) Login(ctx context.Context, email, password string) (*pb.UserInfo, error) {
	query := `
    SELECT 
        id, name, surname, email, birth_date, gender, password_hash, 
        phone_number, address, role, provider, created_at, updated_at, deleted_at
    FROM users 
    WHERE email = $1 AND deleted_at = 0`

	var user pb.UserInfo
	var dbBirthDate sql.NullTime

	err := u.Db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Name,
		&user.Surname,
		&user.Email,
		&dbBirthDate,
		&user.Gender,
		&user.PasswordHash,
		&user.PhoneNumber,
		&user.Address,
		&user.Role,
		&user.Provider,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.DeletedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Parolni tekshirish
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	// Tug'ilgan sanani formatlash
	if dbBirthDate.Valid {
		user.BirthDate = dbBirthDate.Time.Format("2006-01-02")
	} else {
		user.BirthDate = ""
	}

	return &user, nil
}

func (u UserRepository) GetUserByEmail(ctx context.Context, email string) (*pb.UserInfo, error) {
	query := `
    SELECT 
        id, name, surname, email, birth_date, gender, 
        phone_number, address, role, provider, created_at, updated_at, deleted_at
    FROM users 
    WHERE email = $1 AND deleted_at = 0`

	var user pb.UserInfo
	var dbBirthDate sql.NullTime

	err := u.Db.QueryRowContext(ctx, query, email).Scan(
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
		if err == sql.ErrNoRows {
			return nil, nil // User topilmadi, lekin xato emas
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	if dbBirthDate.Valid {
		user.BirthDate = dbBirthDate.Time.Format("2006-01-02")
	} else {
		user.BirthDate = ""
	}

	return &user, nil
}

func (u UserRepository) GetUserById(ctx context.Context, id string) (*pb.UserInfo, error) {
	query := `
    SELECT 
        id, name, surname, email, birth_date, gender, 
        phone_number, address, role, provider, created_at, updated_at, deleted_at
    FROM users 
    WHERE id = $1 AND deleted_at = 0`

	var user pb.UserInfo
	var dbBirthDate sql.NullTime

	err := u.Db.QueryRowContext(ctx, query, id).Scan(
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
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by id: %w", err)
	}

	if dbBirthDate.Valid {
		user.BirthDate = dbBirthDate.Time.Format("2006-01-02")
	} else {
		user.BirthDate = ""
	}

	return &user, nil
}

func (u UserRepository) UserList(
	ctx context.Context,
	filter pb.UserFilter,
	page int64,
	limit int64,
) ([]*pb.UserInfo, int64, error) {
	// Asosiy so'rov
	baseQuery := "FROM users WHERE deleted_at = 0"
	// Hisoblash so'rovi
	countQuery := "SELECT COUNT(*) " + baseQuery

	// Filtrlarni qo'shish
	var args []interface{}
	conditions := []string{}
	argCount := 1

	// Har bir filter uchun shart qo'shish
	if filter.Name != nil {
		conditions = append(conditions, fmt.Sprintf("name ILIKE $%d", argCount))
		args = append(args, "%"+*filter.Name+"%")
		argCount++
	}
	if filter.Surname != nil {
		conditions = append(conditions, fmt.Sprintf("surname ILIKE $%d", argCount))
		args = append(args, "%"+*filter.Surname+"%")
		argCount++
	}
	if filter.Email != nil {
		conditions = append(conditions, fmt.Sprintf("email ILIKE $%d", argCount))
		args = append(args, "%"+*filter.Email+"%")
		argCount++
	}
	if filter.Gender != nil {
		conditions = append(conditions, fmt.Sprintf("gender = $%d", argCount))
		args = append(args, *filter.Gender)
		argCount++
	}
	if filter.Role != nil {
		conditions = append(conditions, fmt.Sprintf("role = $%d", argCount))
		args = append(args, *filter.Role)
		argCount++
	}
	if filter.Provider != nil {
		conditions = append(conditions, fmt.Sprintf("provider = $%d", argCount))
		args = append(args, *filter.Provider)
		argCount++
	}
	if filter.Phone != nil {
		conditions = append(conditions, fmt.Sprintf("phone_number ILIKE $%d", argCount))
		args = append(args, "%"+*filter.Phone+"%")
		argCount++
	}
	if filter.Address != nil {
		conditions = append(conditions, fmt.Sprintf("address ILIKE $%d", argCount))
		args = append(args, "%"+*filter.Address+"%")
		argCount++
	}

	// Filtr shartlarini birlashtirish
	if len(conditions) > 0 {
		whereClause := " AND " + strings.Join(conditions, " AND ")
		baseQuery += whereClause
		countQuery += whereClause
	}

	// Umumiy sonni hisoblash
	var total int64
	err := u.Db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// Ma'lumotlarni olish
	dataQuery := `
    SELECT 
        id, name, surname, email, birth_date, gender, 
        phone_number, address, role, provider, created_at, updated_at, deleted_at
    ` + baseQuery + `
    ORDER BY created_at DESC
    LIMIT $` + strconv.Itoa(argCount) + ` OFFSET $` + strconv.Itoa(argCount+1)

	args = append(args, limit, (page-1)*limit)

	rows, err := u.Db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*pb.UserInfo
	for rows.Next() {
		var user pb.UserInfo
		var dbBirthDate sql.NullTime

		err := rows.Scan(
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
			return nil, 0, fmt.Errorf("failed to scan user: %w", err)
		}

		if dbBirthDate.Valid {
			user.BirthDate = dbBirthDate.Time.Format("2006-01-02")
		} else {
			user.BirthDate = ""
		}

		users = append(users, &user)
	}

	return users, total, nil
}

func (u UserRepository) UpdatePassword(ctx context.Context, email, newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	query := "UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE email = $2"
	result, err := u.Db.ExecContext(ctx, query, string(hashedPassword), email)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no user found with email: %s", email)
	}

	return nil
}

func (u UserRepository) UpdateUser(ctx context.Context, req *pb.UserInfo) (*pb.UserInfo, error) {
	// Sanani formatlash
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
    UPDATE users SET
        name = $1,
        surname = $2,
        email = $3,
        birth_date = $4,
        gender = $5,
        phone_number = $6,
        address = $7,
        role = $8,
        provider = $9,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = $10
    RETURNING 
        id, name, surname, email, birth_date, gender, 
        phone_number, address, role, provider, created_at, updated_at, deleted_at`

	var user pb.UserInfo
	var dbBirthDate time.Time

	err := u.Db.QueryRowContext(ctx, query,
		req.Name,
		req.Surname,
		req.Email,
		birthDate,
		req.Gender,
		sql.NullString{String: req.PhoneNumber, Valid: req.PhoneNumber != ""},
		sql.NullString{String: req.Address, Valid: req.Address != ""},
		req.Role,
		req.Provider,
		req.ID,
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
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	if birthDate.Valid {
		user.BirthDate = birthDate.Time.Format("2006-01-02")
	} else {
		user.BirthDate = ""
	}

	return &user, nil
}

func (u UserRepository) DeleteUser(ctx context.Context, id string) error {
	query := "UPDATE users SET deleted_at = EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) WHERE id = $1"
	result, err := u.Db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no user found with id: %s", id)
	}

	return nil
}

func (u UserRepository) IsUserExist(ctx context.Context, email, phoneNumber string) (bool, error) {
	query := "SELECT EXISTS(SELECT 1 FROM users WHERE (email = $1 OR phone_number = $2) AND deleted_at = 0)"

	var exists bool
	err := u.Db.QueryRowContext(ctx, query, email, phoneNumber).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check user existence: %w", err)
	}

	return exists, nil
}
