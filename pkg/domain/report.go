package domain

import (
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

type ReportItem struct {
	ScanID          uuid.UUID      `json:"scan_id"`
	HostName        string         `json:"host_name"`
	IP              string         `json:"ip"`
	ScanDate        time.Time      `json:"scan_date"`
	TotalSeverities int            `json:"total_severities"`
	CommentStatus   CommmentStatus `json:"comment_status"`
}
