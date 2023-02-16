package mamba

import (
	"errors"
	"github.com/golang-jwt/jwt/v4"
	"time"
)

func NewToken(template *TokenTemplate, body interface{}) (*string, error) {
	if template.SecretKey == "" {
		return nil, errors.New("secret must be a string of at least 1 character")
	}

	var claims tokenClaims
	if template.ExpiryTime > 0 {
		claims = tokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * time.Duration(template.ExpiryTime))),
			},
		}
	} else {
		claims = tokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{},
		}
	}
	claims.Body = body

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

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

func DecodeToken(template *TokenTemplate, tokenString *string) (interface{}, error) {
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


		body, ok := claims["body"]
		if ok {
			return body, nil
		} else {
			return nil, nil
		}
	} else {
		return nil, errors.New("token is invalid")
	}
}