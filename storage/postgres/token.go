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
	// Transaction boshlash
	tx, err := t.Db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// 1. Muddati o'tgan refresh tokenlarni va ularga bog'langan access tokenlarni o'chirish
	refreshExpirationTime := time.Now().AddDate(0, -1, 0) // 1 oy oldin

	// Muddati o'tgan refresh tokenlarni topish
	expiredRefreshQuery := `
	SELECT token
	FROM refreshtokens
	WHERE created_at < $1 AND deleted_at = 0`

	rows, err := tx.QueryContext(ctx, expiredRefreshQuery, refreshExpirationTime)
	if err != nil {
		return fmt.Errorf("failed to get expired refresh tokens: %w", err)
	}
	defer rows.Close()

	var expiredRefreshTokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return fmt.Errorf("failed to scan token: %w", err)
		}
		expiredRefreshTokens = append(expiredRefreshTokens, token)
	}

	// Har bir muddati o'tgan refresh token uchun bog'langan access tokenlarni o'chirish
	for _, rt := range expiredRefreshTokens {
		accessDeleteQuery := `
		UPDATE accestokens
		SET deleted_at = EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)
		WHERE refresh_token = $1 AND deleted_at = 0`

		_, err := tx.ExecContext(ctx, accessDeleteQuery, rt)
		if err != nil {
			return fmt.Errorf("failed to delete access tokens for refresh token %s: %w", rt, err)
		}
	}

	// Muddati o'tgan refresh tokenlarni o'chirish
	refreshDeleteQuery := `
	UPDATE refreshtokens
	SET deleted_at = EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)
	WHERE created_at < $1 AND deleted_at = 0`

	_, err = tx.ExecContext(ctx, refreshDeleteQuery, refreshExpirationTime)
	if err != nil {
		return fmt.Errorf("failed to delete expired refresh tokens: %w", err)
	}

	// 2. Muddati o'tgan access tokenlarni o'chirish (1 soatdan ortiq bo'lganlar)
	accessExpirationTime := time.Now().Add(-1 * time.Hour) // 1 soat oldin
	accessDeleteQuery := `
	UPDATE accestokens
	SET deleted_at = EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)
	WHERE created_at < $1 AND deleted_at = 0`

	_, err = tx.ExecContext(ctx, accessDeleteQuery, accessExpirationTime)
	if err != nil {
		return fmt.Errorf("failed to delete expired access tokens: %w", err)
	}

	// Transactionni tasdiqlash
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
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

func (t TokenRepository) DeleteAccessToken(ctx context.Context, token string) error {
	query := `
	UPDATE accestokens
	SET deleted_at = EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)
	WHERE token = $1`

	result, err := t.Db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to delete access token: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("access token not found")
	}
	return nil
}

// DeleteRefreshTokenAndRelatedAccessTokens - refresh token va unga bog'langan access tokenlarni o'chirish
func (t TokenRepository) DeleteRefreshTokenAndRelatedAccessTokens(ctx context.Context, refreshToken string) error {
	// Transaction boshlash
	tx, err := t.Db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Bog'langan access tokenlarni o'chirish
	accessDeleteQuery := `
	UPDATE accestokens
	SET deleted_at = EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)
	WHERE refresh_token = $1 AND deleted_at = 0`

	_, err = tx.ExecContext(ctx, accessDeleteQuery, refreshToken)
	if err != nil {
		return fmt.Errorf("failed to delete related access tokens: %w", err)
	}

	// Refresh tokenni o'chirish
	refreshDeleteQuery := `
	UPDATE refreshtokens
	SET deleted_at = EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)
	WHERE token = $1 AND deleted_at = 0`

	result, err := tx.ExecContext(ctx, refreshDeleteQuery, refreshToken)
	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	// Hech qanday qator ta'sirlanmaganligini tekshirish
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("refresh token not found")
	}

	// Transactionni tasdiqlash
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// DeleteAllTokensForUser - Foydalanuvchi uchun barcha tokenlarni o'chirish
func (t TokenRepository) DeleteAllTokensForUser(ctx context.Context, userID string) error {
	// Transaction boshlash
	tx, err := t.Db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Userning barcha refresh tokenlarini olish
	refreshTokensQuery := `
	SELECT token
	FROM refreshtokens
	WHERE user_id = $1 AND deleted_at = 0`

	rows, err := tx.QueryContext(ctx, refreshTokensQuery, userID)
	if err != nil {
		return fmt.Errorf("failed to get refresh tokens: %w", err)
	}
	defer rows.Close()

	var refreshTokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return fmt.Errorf("failed to scan token: %w", err)
		}
		refreshTokens = append(refreshTokens, token)
	}

	// Har bir refresh token uchun bog'langan access tokenlarni o'chirish
	for _, rt := range refreshTokens {
		accessDeleteQuery := `
		UPDATE accestokens
		SET deleted_at = EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)
		WHERE refresh_token = $1 AND deleted_at = 0`

		_, err := tx.ExecContext(ctx, accessDeleteQuery, rt)
		if err != nil {
			return fmt.Errorf("failed to delete access tokens for refresh token %s: %w", rt, err)
		}
	}

	// Userning barcha refresh tokenlarini o'chirish
	refreshDeleteQuery := `
	UPDATE refreshtokens
	SET deleted_at = EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)
	WHERE user_id = $1 AND deleted_at = 0`

	_, err = tx.ExecContext(ctx, refreshDeleteQuery, userID)
	if err != nil {
		return fmt.Errorf("failed to delete refresh tokens: %w", err)
	}

	// Transactionni tasdiqlash
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (t TokenRepository) VerifyAccessToken(ctx context.Context, accessToken string) (bool, error) {
	query := `
	SELECT COUNT(*)
	FROM accestokens
	WHERE token = $1 AND deleted_at = 0`

	var count int
	err := t.Db.QueryRowContext(ctx, query, accessToken).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to verify access token: %w", err)
	}
	return count > 0, nil
}
