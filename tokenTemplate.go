package mamba

type TokenTemplate struct {
	// time(in SECONDS) needed for token to expire
	ExpiryTime int64

	// key that is used for signing the token
	JWTSecretKey string
}