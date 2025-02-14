package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ParseCommentStatus_ValidStatuses(t *testing.T) {
	testCases := []struct {
		name           string
		inputString    string
		expectedStatus CommmentStatus
	}{
		{
			name:           "Valid PENDING",
			inputString:    "PENDING",
			expectedStatus: CommentStatusPending,
		},
		{
			name:           "Valid NEW COMMENT",
			inputString:    "NEW COMMENT",
			expectedStatus: CommentStatusNewComment,
		},
		{
			name:           "Valid CRITICAL",
			inputString:    "CRITICAL",
			expectedStatus: CommentStatusCritical,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			status, err := ParseCommentStatus(tc.inputString)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedStatus, status)
		})
	}
}

func Test_ParseCommentStatus_InvalidStatuses(t *testing.T) {
	testCases := []struct {
		name        string
		inputString string
	}{
		{
			name:        "Empty String",
			inputString: "",
		},
		{
			name:        "Invalid Status Lowercase",
			inputString: "pending",
		},
		{
			name:        "Invalid Status Mixed Case",
			inputString: "New Comment",
		},
		{
			name:        "Invalid Status Extra Space",
			inputString: "CRITICAL ",
		},
		{
			name:        "Completely Invalid",
			inputString: "THIS_IS_NOT_A_STATUS",
		},
		{
			name:        "Number",
			inputString: "123",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			status, err := ParseCommentStatus(tc.inputString)
			assert.Error(t, err)
			assert.Equal(t, CommmentStatus(""), status, "Expected empty comment status for invalid input")
			assert.Contains(t, err.Error(), "invalid comment status string")
		})
	}
}
