package mamba

import (
	"errors"

	"github.com/golang-jwt/jwt/v4"
)

// Decode a JWT (`tokenString`) based on `template`
func DecodeToken[T any](template *TokenTemplate, tokenString *string) (*T, error) {
	if template == nil {
		return nil, errors.New("no template provided")
	} else if tokenString == nil {
		return nil, errors.New("no token provided")
	}

	if template.EncryptionKey != "" {
		tmp, err := decryptTokenInternal(tokenString, &template.EncryptionKey)
		if err != nil {
			return nil, err
		}
		tokenString = tmp
	}

	token, err := jwt.ParseWithClaims(*tokenString, &tokenClaims[T]{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}

		return []byte(template.SigningKey), nil
	})

	if err != nil {
		return nil, err
	} else if !token.Valid {
		return nil, errors.New("token is invalid")
	}

	claims, ok := token.Claims.(*tokenClaims[T])
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	if claims.ExpiresAt == nil {
		if template.ExpiryTime != -1 {
			return nil, errors.New("expired token")
		}
	} else {
		if template.ExpiryTime != -1 && !claims.VerifyExpiresAt(decodeTokenNow(), true) {
			return nil, errors.New("expired token")
		}
	}

	return &claims.Body, nil
}
