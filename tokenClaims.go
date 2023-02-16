package mamba

import "github.com/golang-jwt/jwt/v4"

type tokenClaims struct {
	jwt.RegisteredClaims
	Body interface{} `json:"body"`
}