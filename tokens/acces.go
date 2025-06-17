package tokens

import (
	"auth/config"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func GenerateACCESJWTToken(id, role string) (string, error) {
	conf := config.Load()
	token := *jwt.New(jwt.SigningMethodHS256)
	// payload
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = id
	claims["role"] = role
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Hour * 1).Unix()

	newToken, err := token.SignedString([]byte(conf.Token.ACCES_TOKEN_KEY))
	if err != nil {
		return "", err
	}

	return newToken, nil
}

func ValidateACCESToken(tokenStr string) (bool, error) {
	_, err := ExtractClaimACCESToken(tokenStr)
	if err != nil {
		return false, err
	}
	return true, nil
}

func ExtractClaimACCESToken(tokenStr string) (*jwt.MapClaims, error) {
	conf := config.Load()
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return []byte(conf.Token.ACCES_TOKEN_KEY), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !(ok && token.Valid) {
		return nil, err
	}

	return &claims, nil
}

func GetUserInfoFromACCESToken(req string) (Id string, Role string, err error) {
	conf := config.Load()
	Token, err := jwt.Parse(req, func(token *jwt.Token) (interface{}, error) { return []byte(conf.Token.REFRESH_TOKEN_KEY), nil })
	if err != nil || !Token.Valid {
		return "", "", err
	}
	claims, ok := Token.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", err
	}
	Id = claims["user_id"].(string)
	Role = claims["role"].(string)

	return Id, Role, nil
}
