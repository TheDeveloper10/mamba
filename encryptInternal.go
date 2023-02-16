package mamba

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

func encryptTokenInternal(plainToken []byte, key []byte) (*string, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, errors.New("failed to create cipher; probably invalid length")
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
		fmt.Println(err.Error())
        return nil, errors.New("failed to encrypt token")
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.New("failed to encrypt token")
    }
	
    cipherTextHex := gcm.Seal(nonce, nonce, plainToken, nil)
	cipherText := hex.EncodeToString(cipherTextHex)

    return &cipherText, nil
}
