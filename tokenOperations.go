package mamba

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func NewToken[T any](template *TokenTemplate, body *T) (*string, error) {
	if template == nil {
		return nil, errors.New("no template provided")
	} else if template.SigningKey == "" {
		return nil, errors.New("secret must be a string of at least 1 character")
	}

	claims := tokenClaims[T]{
		RegisteredClaims: jwt.RegisteredClaims{},
		Body:             *body,
	}

	if template.ExpiryTime > 0 {
		claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Second * time.Duration(template.ExpiryTime)))
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(template.SigningKey))
	if err != nil {
		return nil, errors.New("failed to sign token")
	}

	return &tokenString, nil
}

func IsTokenValid[T any](template *TokenTemplate, tokenString *string) bool {
	if tokenString == nil {
		return false
	}

	_, err := DecodeToken[T](template, tokenString)
	return err != nil
}

func DecodeToken[T any](template *TokenTemplate, tokenString *string) (*T, error) {
	if template == nil {
		return nil, errors.New("no template provided")
	} else if tokenString == nil {
		return nil, errors.New("no token provided")
	}

	token, err := jwt.ParseWithClaims(*tokenString, &tokenClaims[T]{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}

		return []byte(template.SigningKey), nil
	})

	if err != nil {
		return nil, err
	}

	if token.Valid {
		claims, ok := token.Claims.(*tokenClaims[T])
		if !ok {
			return nil, errors.New("invalid token claims")
		}

		// claims.ExpiresAt
		// exp, ok := claims["exp"].(int64)
		// if ok {
		// 	if exp <= time.Now().Unix() {
		// 		return nil, errors.New("expired token")
		// 	}
		// }

		return &claims.Body, nil
	} else {
		return nil, errors.New("token is invalid")
	}
}
