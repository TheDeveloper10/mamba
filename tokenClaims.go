package mamba

import "github.com/golang-jwt/jwt/v4"

type tokenClaims[T any] struct {
	jwt.RegisteredClaims
	Body T `json:"body"`
}
