package mamba

import (
	"testing"
)

func TestTokenGeneration(t *testing.T) {
	template1 := TokenTemplate{
		ExpiryTime: 10,
		SecretKey:  "abcdefghij",
	}
	template2 := TokenTemplate{
		ExpiryTime: 5,
		SecretKey: "a",
	}
	template3 := TokenTemplate{
		ExpiryTime: 0,
		SecretKey: "c",
	}
	template4 := TokenTemplate{
		ExpiryTime: -1,
		SecretKey: "b",
	}
	template5 := TokenTemplate{
		ExpiryTime: -1,
		SecretKey: "",
	}

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

func tokenGenerationTest(t *testing.T, template *TokenTemplate, body interface{}, shouldError bool) {
	token, err := NewToken(template, body)

	if shouldError {
		if err == nil || token != nil {
			t.Errorf("Error expected")
		}
	} else {
		if err != nil {
			t.Errorf("Unexpected error: %e", err)
		} else if token == nil {
			t.Error("Token is nil")
		} else if len(*token) == 0 {
			t.Error("Token is empty")
		}
	}
}