package mamba

import "testing"

func TestTokenGeneration(t *testing.T) {
	template1 := TokenTemplate{
		ExpiryTime: 10,
		SecretKey:  "abcdefghij",
	}
	template2 := TokenTemplate{
		ExpiryTime: 5,
		SecretKey: "a",
	}
	//template3 := TokenTemplate{
	//	ExpiryTime: 0
	//}

	tokenGenerationTest(t, &template1, "", false)
	tokenGenerationTest(t, &template1, "abc", false)
	tokenGenerationTest(t, &template1, "{\"a\":123}", false)

	tokenGenerationTest(t, &template2, "", false)
	tokenGenerationTest(t, &template2, "abc", false)
	tokenGenerationTest(t, &template2, "{\"a\":123}", false)

}

func tokenGenerationTest(t *testing.T, template *TokenTemplate, body string, shouldError bool) {
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