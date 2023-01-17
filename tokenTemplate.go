package mamba

type TokenTemplate struct {
	// time(in SECONDS) needed for token to expire
	// set to -1 if no token cannot expire
	ExpiryTime int32

	// key that is used for signing the token
	SecretKey string
}