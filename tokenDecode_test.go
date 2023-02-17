package mamba

import (
	"reflect"
	"testing"
	"time"
)

func TestTokenDecode(t *testing.T) {
	decodeTokenNow = func() time.Time { return time.Now().Add(60 * time.Second) }
	defer func() { decodeTokenNow = time.Now }()

	s := func(str string) *string { return &str }
	
	t.Run("parameter test", func(t2 *testing.T) {
		template := TokenTemplate{
			ExpiryTime: 75,
			SigningKey: "b",
		}

		token, _ := NewToken[string](&template, s("a"))
		_, err := DecodeToken[string](nil, token)
		if err == nil {
			t2.Errorf("expected error but got none")
		}

		_, err = DecodeToken[string](nil, nil)
		if err == nil {
			t2.Errorf("expected error but got none")
		}

		_, err = DecodeToken[string](&template, nil)
		if err == nil {
			t2.Errorf("expected error but got none")
		}
	})

	t.Run("dummy test", func(t2 *testing.T) {
		template := TokenTemplate{
			ExpiryTime: 75,
			SigningKey: "b",
		}
		exmToken := ""

		_, err := DecodeToken[string](&template, &exmToken)
		if err == nil {
			t2.Errorf("expected error but got none")
		}
	})

	t.Run("decoding an encrypted token", func(t2 *testing.T) {
		template1 := TokenTemplate{
			ExpiryTime: 75,
			SigningKey: "a",
			EncryptionKey: "1234567890123456",
		}
		template2 := TokenTemplate{
			ExpiryTime: 75,
			SigningKey: "a",
			EncryptionKey: "1234567890123457",
		}

		performTests := func() {
			token, _ := NewToken[string](&template1, s("a"))
			_, err := DecodeToken[string](&template1, token)
			if err != nil {
				t2.Errorf("unexpected error: %e", err)
			}
	
			_, err = DecodeToken[string](&template2, token)
			if err == nil {
				t2.Errorf("expected error but got none")
			}
		}

		performTests()

		template1.EncryptionKey = "123456789012345678901234"
		template2.EncryptionKey = "123456789012345678901235"
		performTests()

		template1.EncryptionKey = "12345678901234567890123456789012"
		template2.EncryptionKey = "12345678901234567890123456789013"
		performTests()
	})

	t.Run("decoding an expired token", func(t2 *testing.T) {
		template := TokenTemplate{
			ExpiryTime: 1,
			SigningKey: "a",
		}

		token, _ := NewToken[string](&template, s("a"))
		_, err := DecodeToken[string](&template, token)
		if err == nil {
			t2.Errorf("expected error but got none")
		}

		template.ExpiryTime = 10

		token, _ = NewToken[string](&template, s("a"))
		_, err = DecodeToken[string](&template, token)
		if err == nil {
			t2.Errorf("expected error but got none")
		}

		template.ExpiryTime = 100

		token, _ = NewToken[string](&template, s("a"))
		_, err = DecodeToken[string](&template, token)
		if err != nil {
			t2.Errorf("unexpected error: %e", err)
		}
	})

	t.Run("same encoding and decoding template", func(t2 *testing.T) {
		template1 := TokenTemplate{
			ExpiryTime: 70,
			SigningKey: "a",
		}
		template2 := TokenTemplate{
			ExpiryTime: 70,
			SigningKey: "b",
		}
		template3 := TokenTemplate{
			ExpiryTime: 70,
			SigningKey: "bcdef",
		}

		token, _ := NewToken[string](&template1, s("a"))
		body, err := DecodeToken[string](&template1, token)
		if err != nil {
			t2.Errorf("unexpected error: %e", err)
		} else if *body != "a" {
			t2.Errorf("incorrect body: %o", body)
		}

		token, _ = NewToken[string](&template2, s("abc"))
		body, err = DecodeToken[string](&template2, token)
		if err != nil {
			t2.Errorf("unexpected error: %e", err)
		} else if *body != "abc" {
			t2.Errorf("incorrect body: %o", body)
		}

		exmBody := testStruct{A: 123, B: "hello world"}
		token, _ = NewToken[testStruct](&template3, &exmBody)
		body2, err := DecodeToken[testStruct](&template3, token)
		if err != nil {
			t2.Errorf("unexpected error: %e", err)
		}
		
		if !reflect.DeepEqual(body2, &exmBody) {
			t2.Errorf("incorrect body - expected: %v but got: %v", exmBody, body2)
		}
	})

	t.Run("different encoding and decoding template", func(t2 *testing.T) {
		template1 := TokenTemplate{
			ExpiryTime: 70,
			SigningKey: "a",
		}
		template2 := TokenTemplate{
			ExpiryTime: 75,
			SigningKey: "b",
		}

		token, _ := NewToken[string](&template1, s("a"))
		_, err := DecodeToken[string](&template2, token)
		if err == nil {
			t2.Errorf("expected error when decoding with a different template")
		}
	})

	t.Run("incorrect tokens", func(t2 *testing.T) {
		template := TokenTemplate{
			ExpiryTime: 1,
			SigningKey: "a",
		}

		token := "aa"
		_, err := DecodeToken[string](&template, &token)
		if err == nil {
			t2.Errorf("expected error but got none")
		}

		token = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AbVUinMiT3J_03je8WTOIl-VdggzvoFgnOsdouAs-DLOtQzau9valrq-S6pETyi9Q18HH-EuwX49Q7m3KC0GuNBJAc9Tksulgsdq8GqwIqZqDKmG7hNmDzaQG1Dpdezn2qzv-otf3ZZe-qNOXUMRImGekfQFIuH_MjD2e8RZyww6lbZk"
		_, err = DecodeToken[string](&template, &token)
		if err == nil {
			t2.Errorf("expected error but got none")
		}

		token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJib2R5IjoiYWFhIn0.FykH134clxQV__pCPFn3JJydLs0DxpT7LopcxQp29-4"
		_, err = DecodeToken[string](&template, &token)
		if err == nil {
			t2.Errorf("expected error but got none")
		}
	})
}

type testStruct struct {
	A int64  `json:"a"`
	B string `json:"b"`
}