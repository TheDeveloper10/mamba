package mamba

type TokenTemplate struct {
	// time(in SECONDS) needed for token to expire
	// set to -1 if tokens cannot expire
	ExpiryTime int32

	// key that is used for signing the token
	// *required
	SigningKey string
}