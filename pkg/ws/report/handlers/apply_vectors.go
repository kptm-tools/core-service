package wshandlers

import (
	"encoding/json"
	"log/slog"
	"math"

	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/dto"
	"github.com/kptm-tools/core-service/pkg/ws/report/reportutils"

	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/ws/common"
)

type ApplyVectorsHandler struct{}

func NewApplyVectorsHandler() *ApplyVectorsHandler {
	return &ApplyVectorsHandler{}
}

func (h *ApplyVectorsHandler) Handle(msg common.Message, client interfaces.IReportClient) error {
	slog.Debug("Handling Apply Vectors message...")

	roomID := client.GetRoomID()
	if roomID == "" {
		return customerrors.NewServerSideError("Client has not joined room")
	}

	scanVulns := client.GetHubReport().GetRoomVulnerabilities(roomID)
	clientStatus := client.GetVectorStatus()

	solved, notSolved := reportutils.FilterVulnerabilitiesByStatus(scanVulns, clientStatus)
	solvedItems := make([]dto.ScanVulnerabilityItem, len(solved))
	notSolvedItems := make([]dto.ScanVulnerabilityItem, len(notSolved))

	for i, vuln := range solved {
		solvedItems[i] = dto.ToScanVulnerabilityItem(vuln)
	}
	for i, vuln := range notSolved {
		notSolvedItems[i] = dto.ToScanVulnerabilityItem(vuln)
	}

	payload := dto.ReportDetailsResponse{
		SolvedVulnerabilities:     solvedItems,
		UnattendedVulnerabilities: notSolvedItems,
		ExpectedSecurityPosture:   getSecurityPostureFromGlobalCVSS(reportutils.GetGlobalCVSSScore(notSolved)),
		GraphData:                 reportutils.BuildVulnerabilityGraph(scanVulns, notSolved),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		slog.Error("Failed to marshal report data response", slog.Any("error", err))
		return customerrors.NewServerSideError("failed to marshal vector update response")
	}

	msgBytes, err := common.BuildServerMessageBytes(dto.MessageReportDataResponse, payloadBytes)
	if err != nil {
		slog.Error("Failed to marshal message", slog.Any("error", err))
		return customerrors.NewServerSideError("failed to marshal message")
	}

	slog.Debug("Sending back response...")
	client.GetSend() <- msgBytes
	return nil
}

// getSecurityPostureFromGlobalCVSS calculates the security posture (e.g: 2%)
// based on a global CVSS (e.g 9.8).
func getSecurityPostureFromGlobalCVSS(cvss float64) float64 {
	result := 1 - (cvss / 10)
	return roundTwoDecimals(result)
}

// roundTwoDecimals rounds a float64 to two decimal places.
func roundTwoDecimals(value float64) float64 {
	shifted := value * 100
	roundedShifted := math.Round(shifted)
	return roundedShifted / 100
}
