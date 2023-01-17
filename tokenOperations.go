package mamba

import (
	"errors"
	"github.com/golang-jwt/jwt/v4"
	"time"
)

func NewToken(template *TokenTemplate, body string) (*string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)

	claims["body"] = body
	if template.ExpiryTime > 0 {
		claims["exp"] = time.Now().Add(time.Second * time.Duration(template.ExpiryTime)).Unix()
	}

	tokenString, err := token.SignedString([]byte(template.SecretKey))
	if err != nil {
		return nil, errors.New("failed to sign token")
	}

	return &tokenString, nil
}

func IsTokenValid(template *TokenTemplate, tokenString *string) bool {
	if tokenString == nil {
		return false
	}

	_, err := DecodeToken(template, tokenString)
	return err != nil
}

func DecodeToken(template *TokenTemplate, tokenString *string) (*string, error) {
	if tokenString == nil {
		return nil, errors.New("no token provided")
	}

	token, err := jwt.Parse(*tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}

		return []byte(template.SecretKey), nil
	})

	if err != nil {
		return nil, err
	}

	if token.Valid {
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, errors.New("invalid token claims")
		}

		exp, ok := claims["exp"].(int64)
		if ok {
			if exp <= time.Now().Unix() {
				return nil, errors.New("expired token")
			}
		}


		body, ok := claims["body"].(string)
		if ok {
			return &body, nil
		} else {
			return nil, nil
		}
	} else {
		return nil, errors.New("token is invalid")
	}
}