package postgres

import (
	"auth/storage/repo"
	"context"
	"database/sql"
	"fmt"
	"time"
)

type TokenRepository struct {
	Db *sql.DB
}

func NewTokenRepository(db *sql.DB) repo.ITokenStorage {
	return &TokenRepository{Db: db}
}

func (t TokenRepository) CreateToken(ctx context.Context, token, userID string) error {
	query := `
	INSERT INTO refreshtokens (token, user_id)
	VALUES ($1, $2)
	ON CONFLICT (token) DO UPDATE
	SET updated_at = CURRENT_TIMESTAMP, deleted_at = 0`

	_, err := t.Db.ExecContext(ctx, query, token, userID)
	if err != nil {
		return fmt.Errorf("failed to create token: %w", err)
	}
	return nil
}

func (t TokenRepository) GetUserIdFromToken(ctx context.Context, token string) (string, error) {
	query := `
	SELECT user_id
	FROM refreshtokens
	WHERE token = $1 AND deleted_at = 0`

	var userID string
	err := t.Db.QueryRowContext(ctx, query, token).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("token not found")
		}
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	return userID, nil
}

func (t TokenRepository) DeleteToken(ctx context.Context, token string) error {
	query := `
	UPDATE refreshtokens
	SET deleted_at = EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)
	WHERE token = $1`

	result, err := t.Db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to delete token: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("token not found")
	}
	return nil
}

func (t TokenRepository) DeleteExpiredTokens(ctx context.Context) error {
	expirationTime := time.Now().AddDate(0, -1, 0)

	query := `
	UPDATE refreshtokens
	SET deleted_at = EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)
	WHERE created_at < $1 AND deleted_at = 0`

	_, err := t.Db.ExecContext(ctx, query, expirationTime)
	if err != nil {
		return fmt.Errorf("failed to delete expired tokens: %w", err)
	}
	return nil
}

func (t TokenRepository) DeleteTokenByUserId(ctx context.Context, userID string) error {
	query := `
	UPDATE refreshtokens
	SET deleted_at = EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)
	WHERE user_id = $1 AND deleted_at = 0`

	_, err := t.Db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete tokens by user ID: %w", err)
	}
	return nil
}

func (t TokenRepository) VerifyToken(ctx context.Context, token string) (bool, error) {
	query := `
	SELECT COUNT(*)
	FROM refreshtokens
	WHERE token = $1 AND deleted_at = 0 AND created_at > CURRENT_TIMESTAMP - INTERVAL '7 days'`

	var count int
	err := t.Db.QueryRowContext(ctx, query, token).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to verify token: %w", err)
	}
	return count > 0, nil
}

func (t TokenRepository) GetTokensByUserID(ctx context.Context, userID string) ([]string, error) {
	query := `
	SELECT token
	FROM refreshtokens
	WHERE user_id = $1 AND deleted_at = 0`

	rows, err := t.Db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tokens by user ID: %w", err)
	}
	defer rows.Close()

	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return nil, fmt.Errorf("failed to scan token: %w", err)
		}
		tokens = append(tokens, token)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return tokens, nil
}

func (t TokenRepository) CreateAccessToken(ctx context.Context, token, refreshToken string) error {
	query := `
	INSERT INTO accestokens (token, refresh_token)
	VALUES ($1, $2)
	ON CONFLICT (token) DO UPDATE
	SET updated_at = CURRENT_TIMESTAMP, deleted_at = 0`

	_, err := t.Db.ExecContext(ctx, query, token, refreshToken)
	if err != nil {
		return fmt.Errorf("failed to create access token: %w", err)
	}
	return nil
}

func (t TokenRepository) GetRefreshTokenByAccesstoken(ctx context.Context, accessToken string) (string, error) {
	query := `
	SELECT refresh_token
	FROM accestokens
	WHERE token = $1 AND deleted_at = 0`

	var refreshToken string
	err := t.Db.QueryRowContext(ctx, query, accessToken).Scan(&refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("access token not found")
		}
		return "", fmt.Errorf("failed to get refresh token: %w", err)
	}
	return refreshToken, nil
}
