package mamba

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
)

func decryptTokenInternal(encryptedToken *string, key *string) (*string, error) {
    block, err := aes.NewCipher([]byte(*key))
    if err != nil {
        return nil, errors.New("failed to create cipher")
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, errors.New("failed to decrypt token")
    }

    cipherBytes, err := hex.DecodeString(*encryptedToken)
    if err != nil {
        return nil, errors.New("failed to decode string")
    }

    nonceSize := gcm.NonceSize()
    if len(cipherBytes) < nonceSize {
        return nil, errors.New("cipher text too short")
    }

    nonce, cipherBytes := cipherBytes[:nonceSize], cipherBytes[nonceSize:]
    plainTokenBytes, err := gcm.Open(nil, nonce, cipherBytes, nil)
    if err != nil {
        return nil, errors.New("failed to decrypt token")
    }

	plainToken := string(plainTokenBytes)

    return &plainToken, nil
}
