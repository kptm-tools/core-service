package utils

import (
	"bytes"
	"testing"
)

func Test_isValidParsing(t *testing.T) {
	// Arrange
	var tests = []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Invalid Json",
			input:    `No Json`,
			expected: false,
		},
		{
			name:     "Valid Json",
			input:    `{ "data" : "good" }`,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := bytes.NewBuffer([]byte(tt.input))
			// Act

			goodResult := true
			if _, err := readFileJson(buf); err != nil {
				goodResult = false
			}
			// Assert
			if goodResult != tt.expected {
				t.Errorf("Incorrect result, expected `%v`, got `%v`", tt.expected, goodResult)
			}

		})
	}
}
