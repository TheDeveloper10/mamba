package mamba

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
)

func encryptTokenInternal(plainToken *string, key *string) (*string, error) {
    block, err := aes.NewCipher([]byte(*key))
    if err != nil {
        return nil, errors.New("failed to create cipher")
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, errors.New("failed to encrypt token")
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = gcm.Open(nil, nonce, []byte(*plainToken), nil); err != nil {
        return nil, errors.New("failed to encrypt token")
    }

    cipherTextHex := gcm.Seal(nonce, nonce, []byte(*plainToken), nil)
	cipherText := hex.EncodeToString(cipherTextHex)

    return &cipherText, nil
}
