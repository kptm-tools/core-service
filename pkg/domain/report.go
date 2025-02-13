package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type CommmentStatus string

const (
	CommentStatusPending    CommmentStatus = "PENDING"
	CommentStatusNewComment CommmentStatus = "NEW COMMENT"
	CommentStatusCritical   CommmentStatus = "CRITICAL"
)

func (cs CommmentStatus) String() string {
	return string(cs)
}

func ParseCommentStatus(statusString string) (CommmentStatus, error) {
	switch statusString {
	case "PENDING":
		return CommentStatusPending, nil
	case "NEW COMMENT":
		return CommentStatusNewComment, nil
	case "CRITICAL":
		return CommentStatusCritical, nil
	default:
		return "", fmt.Errorf("invalid comment status string: %s", statusString)
	}
}

type ReportItem struct {
	ScanID          uuid.UUID      `json:"scan_id"`
	HostName        string         `json:"host_name"`
	IP              string         `json:"ip"`
	ScanDate        time.Time      `json:"scan_date"`
	TotalSeverities int            `json:"total_severities"`
	CommentStatus   CommmentStatus `json:"comment_status"`
}

type ScoreCardTrendItem struct {
	Alias            string
	OldestScore      *float64
	LatestScore      *float64
	LatestScoreGrade *string
}

// calculateScoreGrade calculates the letter grade (A-F) based on the protection score.
// It handles nil scores by returning an empty string as grade.
func calculateScoreGrade(score *float64) *string {
	if score == nil {
		return nil
	}

	var grade string
	if *score >= 0.9 {
		grade = "A"
	} else if *score >= 0.8 {
		grade = "B"
	} else if *score >= 0.7 {
		grade = "C"
	} else if *score >= 0.6 {
		grade = "D"
	} else {
		grade = "F"
	}

	return &grade
}

func NewScoreCardTrendItem(alias string, oldestScore, latestScore *float64) *ScoreCardTrendItem {
	latestScoreGrade := calculateScoreGrade(latestScore)

	return &ScoreCardTrendItem{
		Alias:            alias,
		OldestScore:      oldestScore,
		LatestScore:      latestScore,
		LatestScoreGrade: latestScoreGrade,
	}
}
