package mamba

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
)


// the only reason for these to exist is testing
var (
	newTokenNow    = time.Now
	decodeTokenNow = time.Now
)

/*
Generate a new JWT with a `body` from `template`
*/
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

	return &tokenString, nil
}

/*
Check whether a JWT (`tokenString`) is valid based on `template`
*/
func IsTokenValid[T any](template *TokenTemplate, tokenString *string) (bool, error) {
	if template == nil {
		return false, errors.New("no template provided")
	} else if tokenString == nil {
		return false, errors.New("no token provided")
	}

	_, err := DecodeToken[T](template, tokenString)
	return err != nil, err
}

/*
Decode a JWT (`tokenString`) based on `template`
*/
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
	} else {
		return nil, errors.New("token is invalid")
	}
}
