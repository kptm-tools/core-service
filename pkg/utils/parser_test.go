package utils

import (
	"bytes"
	"testing"
)

func Test_isValidParsing(t *testing.T) {
	var buffer1 bytes.Buffer
	buffer1.WriteString(`{ "data" : "good" }`)
	var buffer2 bytes.Buffer
	buffer2.WriteString(`No Json`)
	var buffer3 bytes.Buffer
	buffer3.WriteString(`{ }`)
	// Arrange
	var tests = []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Invalid Json",
			input:    buffer2,
			expected: false,
		},
		{
			name:     "Valid Json",
			input:    buffer1,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Act
			result := isValidDatabaseName(tt.input)

			// Assert
			if result != tt.expected {
				t.Errorf("Incorrect result, expected `%v`, got `%v`", tt.expected, result)
			}

		})
	}
}
