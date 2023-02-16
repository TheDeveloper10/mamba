package mamba

type TokenTemplate struct {
	// time(in SECONDS) needed for token to expire
	// set to -1 if tokens cannot expire
	ExpiryTime int32

	// key that is used for signing the token
	// *required
	SigningKey string

	// key that is used for encrypting the token after signing
	// must be either 16, 24, 32 characters long!
	// optional
	EncryptionKey string
}