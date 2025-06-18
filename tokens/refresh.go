package tokens

import (
	"auth/config"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func GenerateRefreshJWTToken(id, role string) (string, error) {
	conf := config.Load()
	token := *jwt.New(jwt.SigningMethodHS256)
	// payload
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = id
	claims["role"] = role
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().AddDate(0, 1, 0).Unix()

	newToken, err := token.SignedString([]byte(conf.Token.REFRESH_TOKEN_KEY))
	if err != nil {
		return "", err
	}

	return newToken, nil
}

func ValidateRefreshToken(tokenStr string) (bool, error) {
	_, err := ExtractClaimRefreshToken(tokenStr)
	if err != nil {
		return false, err
	}
	return true, nil
}

func ExtractClaimRefreshToken(tokenStr string) (*jwt.MapClaims, error) {
	conf := config.Load()
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return []byte(conf.Token.REFRESH_TOKEN_KEY), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, err
	}

	return &claims, nil
}

func GetUserInfoFromRefreshToken(req string) (id string, role string, err error) {
	conf := config.Load()
	Token, err := jwt.Parse(req, func(token *jwt.Token) (interface{}, error) { return []byte(conf.Token.REFRESH_TOKEN_KEY), nil })
	if err != nil || !Token.Valid {
		return "", "", err
	}
	claims, ok := Token.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", err
	}
	id = claims["user_id"].(string)
	role = claims["role"].(string)

	return id, role, nil
}
