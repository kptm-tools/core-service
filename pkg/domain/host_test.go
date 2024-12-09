package domain

import "testing"

func Test_IsValidDomain(t *testing.T) {

	// Arrange

	var tests = []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Valid domain name without scheme",
			input:    "example.com",
			expected: true,
		},
		{
			name:     "Valid domain name with 'www' subdomain",
			input:    "www.example.com",
			expected: true,
		},
		{
			name:     "Valid domain name with 'http' scheme",
			input:    "http://example.com",
			expected: false,
		},
		{
			name:     "Valid domain name with 'https' scheme",
			input:    "https://example.com",
			expected: false,
		},
		{
			name:     "Valid domain name with 'http' scheme and 'www' subdomain",
			input:    "http://www.example.com",
			expected: false,
		},
		{
			name:     "Valid domain name with 'https' scheme and 'www' subdomain",
			input:    "https://www.example.com",
			expected: false,
		},
		{
			name:     "Valid domain name with subdomain",
			input:    "subdomain.example.com",
			expected: true,
		},
		{
			name:     "Invalid domain name with incorrect syntax",
			input:    "subdomain,example,com",
			expected: false,
		},
	}
	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			// Act
			result := IsValidDomain(tt.input)

			// Assert
			if result != tt.expected {
				t.Errorf("Incorrect result, expected `%v` got `%v`", tt.expected, result)
			}

		})

	}
}

func TestExtractDomain(t *testing.T) {

	var tests = []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Invalid domain name without scheme",
			input:    "example.com",
			expected: "",
		},
		{
			name:     "Invalid domain name with 'www' subdomain without scheme",
			input:    "www.example.com",
			expected: "",
		},
		{
			name:     "Valid domain name with 'http' scheme",
			input:    "http://example.com",
			expected: "example.com",
		},
		{
			name:     "Valid domain name with 'https' scheme",
			input:    "https://example.com",
			expected: "example.com",
		},
		{
			name:     "Valid domain name with 'http' scheme and 'www' subdomain",
			input:    "http://www.example.com",
			expected: "www.example.com",
		},
		{
			name:     "Valid domain name with 'https' scheme and 'www' subdomain",
			input:    "https://www.example.com",
			expected: "www.example.com",
		},
		{
			name:     "Invalid domain name with subdomain without scheme",
			input:    "subdomain.example.com",
			expected: "",
		},
		{
			name:     "Invalid domain name with incorrect syntax without scheme",
			input:    "subdomain,example,com",
			expected: "",
		},
	}
	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			// Act
			result, _ := ExtractDomainFromURL(tt.input)

			// Assert
			if result != tt.expected {
				t.Errorf("Incorrect result, expected `%v` got `%v`", tt.expected, result)
			}

		})

	}
}
