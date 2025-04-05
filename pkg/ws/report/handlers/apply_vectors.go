package wshandlers

import (
	"log/slog"

	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/ws/common"
)

const MessageApplyVectors = "apply_vectors_request"

// ApplyVectorsMessage is the payload sent in a MessageApplyVectors
type ApplyVectorsMessage struct{}

type ReportDetailsResponse struct {
	SolvedVulnerabilities     tools.Vulnerability `json:"solved_vulnerabilities"`
	UnattendedVulnerabilities tools.Vulnerability `json:"unattended_vulnerabilities"`
	ExpectedSecurityPosture   float64             `json:"expected_security_posture"`
}

type ApplyVectorsHandler struct{}

func NewApplyVectorsHandler() *ApplyVectorsHandler {
	return &ApplyVectorsHandler{}
}

func (h *ApplyVectorsHandler) Handle(msg common.Message, client interfaces.IReportClient) error {
	slog.Debug("Handling Apply Vectors message...")
	return nil
}
