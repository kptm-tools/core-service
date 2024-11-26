package storage

import "testing"

func Test_isValidDatabaseName(t *testing.T) {

	// Arrange
	var tests = []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Valid database name that starts with letter",
			input:    "my_db",
			expected: true,
		},
		{
			name:     "Valid database name that starts with underscore",
			input:    "_my_db",
			expected: true,
		},
		{
			name:     "Valid database name that contains capital letter",
			input:    "my_dB",
			expected: true,
		},
		{
			name:     "Invalid database name that contains quotes",
			input:    `"my_dB"`,
			expected: false,
		},
		{
			name:     "Invalid database name that contains special character @",
			input:    `my_dB@`,
			expected: false,
		},
		{
			name:     "Invalid database name that contains special character -",
			input:    `my_dB-`,
			expected: false,
		},
		{
			name:     "Invalid database name that contains special character !",
			input:    `my_dB!`,
			expected: false,
		},
		{
			name:     "Invalid database name that contains special character #",
			input:    `my_dB#`,
			expected: false,
		},
		{
			name:     "Invalid database name that contains special character %",
			input:    `my_dB%`,
			expected: false,
		},
		{
			name:     "Invalid database name that contains special character ^",
			input:    `my_dB^`,
			expected: false,
		},
		{
			name:     "Invalid database name that contains special character &",
			input:    `my_dB&`,
			expected: false,
		},
		{
			name:     "Invalid database name that contains special character *",
			input:    `my_dB*`,
			expected: false,
		},
		{
			name:     "Invalid database name that is empty",
			input:    ``,
			expected: false,
		},
		{
			name:     "Invalid database name that longer that 62 chars",
			input:    `superduperwhooperlongdatabasenamethatislongerthansixtythreecharacters`,
			expected: false,
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
