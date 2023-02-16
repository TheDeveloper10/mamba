package mamba

import "errors"

// Check whether a JWT (`tokenString`) is valid based on `template`
func IsTokenValid[T any](template *TokenTemplate, tokenString *string) (bool, error) {
	if template == nil {
		return false, errors.New("no template provided")
	} else if tokenString == nil {
		return false, errors.New("no token provided")
	}

	_, err := DecodeToken[T](template, tokenString)
	return err != nil, err
}
