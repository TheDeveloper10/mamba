package mamba

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Generate a new JWT with a `body` from `template`
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
		claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(newTokenNow().Add(time.Second * time.Duration(template.ExpiryTime)))
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(template.SigningKey))
	if err != nil {
		return nil, errors.New("failed to sign token")
	}

	if template.EncryptionKey != "" {
		return encryptTokenInternal([]byte(tokenString), []byte(template.EncryptionKey))
	} else {
		return &tokenString, nil
	}
}