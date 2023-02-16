package mamba

import (
	"testing"
)

func TestTokenGeneration(t *testing.T) {
	type tempTemplate struct {
		TokenTemplate
		shouldError bool
	}

	templates := []tempTemplate{
		{shouldError: false, TokenTemplate: TokenTemplate{ExpiryTime: 10, SigningKey: "abcdefghij"}},
		{shouldError: false, TokenTemplate: TokenTemplate{ExpiryTime: 5, SigningKey: "a"}},
		{shouldError: false, TokenTemplate: TokenTemplate{ExpiryTime: 0, SigningKey: "c"}},
		{shouldError: false, TokenTemplate: TokenTemplate{ExpiryTime: -1, SigningKey: "b"}},
		{shouldError: true, TokenTemplate: TokenTemplate{ExpiryTime: -1, SigningKey: ""}},
		{shouldError: false, TokenTemplate: TokenTemplate{ExpiryTime: 10, SigningKey: "abcd"}},
		{shouldError: false, TokenTemplate: TokenTemplate{ExpiryTime: -1, SigningKey: "abcd"}},
		{shouldError: true, TokenTemplate: TokenTemplate{ExpiryTime: 10, SigningKey: "abcd", EncryptionKey: "1234"}},
		{shouldError: true, TokenTemplate: TokenTemplate{ExpiryTime: -1, SigningKey: "abcd", EncryptionKey: "1234"}},
		{shouldError: true, TokenTemplate: TokenTemplate{ExpiryTime: 100, SigningKey: "abcd", EncryptionKey: "01234567890123456"}},
		{shouldError: false, TokenTemplate: TokenTemplate{ExpiryTime: 100, SigningKey: "abcd", EncryptionKey: "1234567890123456"}},
		{shouldError: false, TokenTemplate: TokenTemplate{ExpiryTime: 10, SigningKey: "abcd", EncryptionKey: "1234567890123456"}},
		{shouldError: false, TokenTemplate: TokenTemplate{ExpiryTime: -1, SigningKey: "abcd", EncryptionKey: "1234567890123456"}},
		{shouldError: true, TokenTemplate: TokenTemplate{ExpiryTime: 100, SigningKey: "abcd", EncryptionKey: "0123456789012345678901234"}},
		{shouldError: false, TokenTemplate: TokenTemplate{ExpiryTime: 100, SigningKey: "abcd", EncryptionKey: "123456789012345678901234"}},
		{shouldError: false, TokenTemplate: TokenTemplate{ExpiryTime: 10, SigningKey: "abcd", EncryptionKey: "123456789012345678901234"}},
		{shouldError: false, TokenTemplate: TokenTemplate{ExpiryTime: -1, SigningKey: "abcd", EncryptionKey: "123456789012345678901234"}},
		{shouldError: true, TokenTemplate: TokenTemplate{ExpiryTime: 100, SigningKey: "abcd", EncryptionKey: "012345678901234567890123456789012"}},
		{shouldError: false, TokenTemplate: TokenTemplate{ExpiryTime: 100, SigningKey: "abcd", EncryptionKey: "12345678901234567890123456789012"}},
		{shouldError: false, TokenTemplate: TokenTemplate{ExpiryTime: 10, SigningKey: "abcd", EncryptionKey: "12345678901234567890123456789012"}},
		{shouldError: false, TokenTemplate: TokenTemplate{ExpiryTime: -1, SigningKey: "abcd", EncryptionKey: "12345678901234567890123456789012"}},
	}

	tokenGenerationTest(t, 0, nil, 2, true)

	for id, template := range templates {
		tokenGenerationTest(t, id, &template.TokenTemplate, "", template.shouldError)
		tokenGenerationTest(t, id, &template.TokenTemplate, "abc", template.shouldError)
		tokenGenerationTest(t, id, &template.TokenTemplate, "{\"a\":123}", template.shouldError)
		tokenGenerationTest(t, id, &template.TokenTemplate, 2, template.shouldError)
	}
}

func tokenGenerationTest[T any](t *testing.T, id int, template *TokenTemplate, body T, shouldError bool) {
	id++
	token, err := NewToken(template, &body)

	if shouldError {
		if err == nil || token != nil {
			t.Errorf("%d: error expected", id)
		}
	} else {
		if err != nil {
			t.Errorf("%d: unexpected error: %e", id, err)
		} else if token == nil {
			t.Errorf("%d: token is nil", id)
		} else if len(*token) == 0 {
			t.Errorf("%d: token is empty", id)
		}
	}
}
