package consumers

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

// handleToolResultError processes the result of a tool's execution.
// It logs errors, differentiates between skipped tools and actual failures,
// and marks the overall scan as failed if a genuine failure occurs.
//
// Parameters:
// scanID: The UUID of the scan this tool result belongs to.
// toolResult: The result object from a single tool execution, including its error struct.
// scanService: An instance of IScanService to interact with scan status.
func handleToolResultError(ctx context.Context, scanID uuid.UUID, toolRes tools.ToolResult, scanService interfaces.IScanService) {
	if toolRes.Err == nil {
		return
	}

	slog.Warn("ToolResult indicates an issue",
		slog.String("scan_id", scanID.String()),
		slog.String("tool_name", toolRes.Tool.String()),
		slog.String("error_code", string(toolRes.Err.Code)),
		slog.String("reason", toolRes.Err.Message),
	)

	// Differentiate between a skipped tool and a genuine failure.
	if toolRes.Err.Code == enums.ToolSkippedError {
		// Log explicitly that the tool was skipped.
		slog.Info("Tool skipped for target due to incompatibility",

			slog.String("scan_id", scanID.String()),
			slog.String("tool_name", toolRes.Tool.String()),
			slog.String("error_code", string(toolRes.Err.Code)),
			slog.String("reason", toolRes.Err.Message),
		)
	} else {
		// This is a genuine tool failure, so mark the overall scan as failed.
		slog.Error("Tool failed for target, marking scan as failed",
			slog.String("scan_id", scanID.String()),
			slog.String("tool_name", toolRes.Tool.String()),
			slog.String("error_code", string(toolRes.Err.Code)),
			slog.String("error_message", toolRes.Err.Message),
		)
		if err := scanService.MarkScanAsFailed(ctx, scanID); err != nil {
			slog.Error("Failed to mark scan as failed",
				slog.String("scan_id", scanID.String()),
				slog.Any("error", err),
			)
		} else {
			slog.Debug("Scan status successfully marked as failed", slog.String("scan_id", scanID.String()))
		}
	}
}
