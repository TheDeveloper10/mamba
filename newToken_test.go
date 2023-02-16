package mamba

import (
	"testing"
)

func TestTokenGeneration(t *testing.T) {
	template1 := TokenTemplate{
		ExpiryTime: 10,
		SigningKey:  "abcdefghij",
	}
	template2 := TokenTemplate{
		ExpiryTime: 5,
		SigningKey: "a",
	}
	template3 := TokenTemplate{
		ExpiryTime: 0,
		SigningKey: "c",
	}
	template4 := TokenTemplate{
		ExpiryTime: -1,
		SigningKey: "b",
	}
	template5 := TokenTemplate{
		ExpiryTime: -1,
		SigningKey: "",
	}

	tokenGenerationTest(t, nil, 2, true)

	tokenGenerationTest(t, &template1, "", false)
	tokenGenerationTest(t, &template1, "abc", false)
	tokenGenerationTest(t, &template1, "{\"a\":123}", false)
	tokenGenerationTest(t, &template1, 2, false)

	tokenGenerationTest(t, &template2, "", false)
	tokenGenerationTest(t, &template2, "abc", false)
	tokenGenerationTest(t, &template2, "{\"a\":123}", false)
	tokenGenerationTest(t, &template2, 2, false)

	tokenGenerationTest(t, &template3, "", false)
	tokenGenerationTest(t, &template3, "abc", false)
	tokenGenerationTest(t, &template3, "{\"a\":123}", false)
	tokenGenerationTest(t, &template3, 2, false)

	tokenGenerationTest(t, &template4, "", false)
	tokenGenerationTest(t, &template4, "abc", false)
	tokenGenerationTest(t, &template4, "{\"a\":123}", false)
	tokenGenerationTest(t, &template4, 2, false)

	tokenGenerationTest(t, &template5, "", true)
	tokenGenerationTest(t, &template5, "abc", true)
	tokenGenerationTest(t, &template5, "{\"a\":123}", true)
	tokenGenerationTest(t, &template5, 2, true)

}

func tokenGenerationTest[T any](t *testing.T, template *TokenTemplate, body T, shouldError bool) {
	token, err := NewToken(template, &body)

	if shouldError {
		if err == nil || token != nil {
			t.Errorf("error expected")
		}
	} else {
		if err != nil {
			t.Errorf("unexpected error: %e", err)
		} else if token == nil {
			t.Error("token is nil")
		} else if len(*token) == 0 {
			t.Error("token is empty")
		}
	}
}