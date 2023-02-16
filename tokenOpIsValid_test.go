package mamba

import "testing"

func TestTokenIsValid(t *testing.T) {
	s := func(str string) *string { return &str }

	t.Run("parameter test", func(t2 *testing.T) {
		template := TokenTemplate{
			ExpiryTime: 75,
			SigningKey: "b",
		}

		token, _ := NewToken[string](&template, s("a"))
		_, err := IsTokenValid[string](nil, token)
		if err == nil {
			t2.Errorf("expected error but got none")
		}

		_, err = IsTokenValid[string](nil, nil)
		if err == nil {
			t2.Errorf("expected error but got none")
		}

		_, err = IsTokenValid[string](&template, nil)
		if err == nil {
			t2.Errorf("expected error but got none")
		}
	})

	// there's no need for other tests since it literally calls `DecodeToken`
}