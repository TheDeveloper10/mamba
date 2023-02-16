package mamba

import "testing"

func TestEncryptInternal(t *testing.T) {
	type eiTest struct {
		expectedError bool
		plainToken    string
		key           string
	}

	tests := []eiTest{
		{expectedError: false, plainToken: "a", key: "1234567890123456"},
		{expectedError: false, plainToken: "a", key: "123456789012345678901234"},
		{expectedError: false, plainToken: "a", key: "12345678901234567890123456789012"},
		{expectedError: false, plainToken: "ab", key: "1234567890123456"},
		{expectedError: false, plainToken: "ab", key: "123456789012345678901234"},
		{expectedError: false, plainToken: "ab", key: "12345678901234567890123456789012"},
		{expectedError: false, plainToken: "abc", key: "1234567890123456"},
		{expectedError: false, plainToken: "abc", key: "123456789012345678901234"},
		{expectedError: false, plainToken: "abc", key: "12345678901234567890123456789012"},
		{expectedError: false, plainToken: "abcd", key: "1234567890123456"},
		{expectedError: false, plainToken: "abcd", key: "123456789012345678901234"},
		{expectedError: false, plainToken: "abcd", key: "12345678901234567890123456789012"},
		{expectedError: false, plainToken: "abcde", key: "1234567890123456"},
		{expectedError: false, plainToken: "abcde", key: "123456789012345678901234"},
		{expectedError: false, plainToken: "abcde", key: "12345678901234567890123456789012"},
		{expectedError: false, plainToken: "abcdef", key: "1234567890123456"},
		{expectedError: false, plainToken: "abcdef", key: "123456789012345678901234"},
		{expectedError: false, plainToken: "abcdef", key: "12345678901234567890123456789012"},

		{expectedError: true, plainToken: "aaa", key: ""},
		{expectedError: true, plainToken: "aaa", key: "1"},
		{expectedError: true, plainToken: "aaa", key: "12"},
		{expectedError: true, plainToken: "aaa", key: "123"},
		{expectedError: true, plainToken: "aaa", key: "1234"},
		{expectedError: true, plainToken: "aaa", key: "12345"},
		{expectedError: true, plainToken: "aaa", key: "123456"},
		{expectedError: true, plainToken: "aaa", key: "1234567"},
		{expectedError: true, plainToken: "aaa", key: "12345678"},
		{expectedError: true, plainToken: "aaa", key: "123456789"},
		{expectedError: true, plainToken: "aaa", key: "1234567890"},
		{expectedError: true, plainToken: "aaa", key: "12345678901"},
		{expectedError: true, plainToken: "aaa", key: "123456789012"},
		{expectedError: true, plainToken: "aaa", key: "1234567890123"},
		{expectedError: true, plainToken: "aaa", key: "12345678901234"},
		{expectedError: true, plainToken: "aaa", key: "123456789012345"},
	}

	for testId, test := range tests {
		_, err := encryptInternal([]byte(test.plainToken), []byte(test.key))
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
