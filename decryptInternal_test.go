package mamba

import "testing"

func TestDecryptInternal(t *testing.T) {
	type diTest struct {
		expectedError  bool
		
		plainToken     string
		encryptedToken string

		encKey         string
		decKey         string
	}

	tests := []diTest{
		{expectedError: false, plainToken: "a", encKey: "1234567890123456"},
		{expectedError: false, plainToken: "ab", encKey: "1234567890123456"},
		{expectedError: false, plainToken: "abc", encKey: "1234567890123456"},
		{expectedError: false, plainToken: "abcd", encKey: "1234567890123456"},
		{expectedError: false, plainToken: "a", encKey: "123456789012345678901234"},
		{expectedError: false, plainToken: "a", encKey: "12345678901234567890123456789012"},

		{expectedError: true, plainToken: "a", encKey: "1234567890123456", decKey: "1234567890123457"},
		{expectedError: true, plainToken: "a", encKey: "1234567890123456", decKey: "12345678901234578"},
		{expectedError: true, plainToken: "ab", encKey: "1234567890123456", decKey: "1234567890123457"},
		{expectedError: true, plainToken: "abc", encKey: "1234567890123456", decKey: "1234567890123457"},
		{expectedError: true, plainToken: "abcd", encKey: "1234567890123456", decKey: "1234567890123457"},
		{expectedError: true, encryptedToken: "a", decKey: "1234567890123456"},
		{expectedError: true, encryptedToken: "ab", decKey: "1234567890123456"},
		{expectedError: true, encryptedToken: "abc", decKey: "1234567890123456"},
		{expectedError: true, encryptedToken: "abcd", decKey: "1234567890123456"},
	}

	for testId, test := range tests {
		if test.plainToken != "" {
			plainToken, _ := encryptInternal([]byte(test.plainToken), []byte(test.encKey))
			test.encryptedToken = *plainToken
		}
		
		decKey := test.decKey
		if decKey == "" {
			decKey = test.encKey
		}

		_, err := decryptInternal(&test.encryptedToken, []byte(decKey))
		if err == nil {
			if test.expectedError {
				t.Errorf("%d: expected error but got none", testId)
			}
		} else {
			if !test.expectedError {
				t.Errorf("%d: unexpected error: %e", testId, err)
			}
		}
	}
}
