package mamba

import (
	"reflect"
	"testing"
)

func TestTokenDecode(t *testing.T) {
	t.Run("Same encoding template and decoding template", func(t2 *testing.T) {
		template1 := TokenTemplate{
			ExpiryTime: 10,
			SigningKey: "a",
		}
		template2 := TokenTemplate{
			ExpiryTime: 10,
			SigningKey: "b",
		}
		template3 := TokenTemplate{
			ExpiryTime: 10,
			SigningKey: "bcdef",
		}

		s := func(str string) *string { return &str }

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
	//token, _ := NewToken(&template1, "a")
	//DecodeToken(template1, tokens)
}

type testStruct struct {
	A int64  `json:"a"`
	B string `json:"b"`
}