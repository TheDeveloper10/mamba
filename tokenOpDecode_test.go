package mamba

import (
	"reflect"
	"testing"
)

func TestTokenDecode(t *testing.T) {
	t.Run("Same encoding template and decoding template", func(t2 *testing.T) {
		template1 := TokenTemplate{
			ExpiryTime: 10,
			SecretKey: "a",
		}
		template2 := TokenTemplate{
			ExpiryTime: 10,
			SecretKey: "b",
		}
		template3 := TokenTemplate{
			ExpiryTime: 10,
			SecretKey: "bcdef",
		}

		token, _ := NewToken(&template1, "a")
		body, err := DecodeToken(&template1, token)
		if err != nil {
			t2.Errorf("unexpected error: %e", err)
		} else if body != "a" {
			t2.Errorf("incorrect body: %o", body)
		}

		token, _ = NewToken(&template2, "abc")
		body, err = DecodeToken(&template2, token)
		if err != nil {
			t2.Errorf("unexpected error: %e", err)
		} else if body != "abc" {
			t2.Errorf("incorrect body: %o", body)
		}

		exmBody := testStruct{a: 123, b: "hello world"}
		token, _ = NewToken(&template3, exmBody)
		body, err = DecodeToken(&template3, token)
		if err != nil {
			t2.Errorf("unexpected error: %e", err)
		} else if !reflect.DeepEqual(body.(testStruct), exmBody) {
			t2.Errorf("incorrect body: %o", body)
		}
	})
	//token, _ := NewToken(&template1, "a")
	//DecodeToken(template1, tokens)
}

type testStruct struct {
	a int64
	b string
}