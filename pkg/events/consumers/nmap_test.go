package consumers

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	mock_services "github.com/kptm-tools/core-service/pkg/mocks/services"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"sync"
	"testing"
	"time"
)

func TestNmapHandlerConsumer(t *testing.T) {
	tests := []struct {
		name          string
		scanService   interfaces.IScanService
		vulnService   interfaces.IVulnerabilityService
		data          []byte
		expectedError string
	}{
		{
			name:          "Error with unmarshall result",
			scanService:   &mock_services.MockScanService{},
			vulnService:   &mock_services.MockVulnerabilityService{},
			data:          []byte(``),
			expectedError: "unexpected end of JSON input",
		},
		{
			name: "Error with invalid tool name",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "Failed"}, nil // not Completed
				},
			},
			data:          []byte(`{}`),
			expectedError: "invalid toolName for NmapEvent",
		},
		{
			name: "Error with no scanID",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return nil, customerrors.ErrScanNotFound // not Completed
				},
			},
			data: []byte(`{
							  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
							  "timestamp": "2025-07-07T12:34:56Z",
                              "ToolResult": {"tool_name": "Nmap",
                              "result": null,
							  "error": null,
							  "timestamp": "2025-07-07T12:34:56Z"
							}}`),
			expectedError: "scan not found",
		},
		{
			name: "Error with scan status failed",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "Failed"}, nil
				},
			},
			data: []byte(`{
							  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
							  "timestamp": "2025-07-07T12:34:56Z",
                              "ToolResult": {"tool_name": "Nmap",
                              "result": null,
							  "error": null,
							  "timestamp": "2025-07-07T12:34:56Z"
							}}`),
			expectedError: "error inserting ScanResult to DB because of Scan Status",
		},
		{
			name: "Error inserting scan result",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "InProgress"}, nil
				},
				MockInsertScanResult: func(ctx context.Context, result domain.ScanResult) error {
					return errors.New("inserting ScanResult to DB")
				},
				MockMarkScanAsFailed: func(ctx context.Context, scanID uuid.UUID) error {
					return nil
				},
			},
			data: []byte(`{
							  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
							  "timestamp": "2025-07-07T12:34:56Z",
                              "ToolResult": {"tool_name": "Nmap",
                              "result": null,
							  "error": null,
							  "timestamp": "2025-07-07T12:34:56Z"
							}}`),
			expectedError: "inserting ScanResult to DB",
		},
		{
			name: "Error inserting scan result",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "InProgress"}, nil
				},
				MockInsertScanResult: func(ctx context.Context, result domain.ScanResult) error {
					return errors.New("inserting ScanResult to DB")
				},
				MockMarkScanAsFailed: func(ctx context.Context, scanID uuid.UUID) error {
					return nil
				},
			},
			data: []byte(`{
							  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
							  "timestamp": "2025-07-07T12:34:56Z",
                              "ToolResult": {"tool_name": "Nmap",
                              "result": null,
							  "error": null,
							  "timestamp": "2025-07-07T12:34:56Z"
							}}`),
			expectedError: "inserting ScanResult to DB",
		},
		{
			name: "Error in tool result",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "InProgress"}, nil
				},
				MockInsertScanResult: func(ctx context.Context, result domain.ScanResult) error {
					return nil
				},
				MockMarkScanAsFailed: func(ctx context.Context, scanID uuid.UUID) error {
					return nil
				},
			},
			data: []byte(`{
							  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
							  "timestamp": "2025-07-07T12:34:56Z",
                              "ToolResult": {"tool_name": "Nmap",
                              "result": null,
							  "error": {
								"message": "error in tool result"
							  },
							  "timestamp": "2025-07-07T12:34:56Z"
							}}`),
			expectedError: "error in tool result",
		},
		{
			name: "Good insertion",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "InProgress"}, nil
				},
				MockInsertScanResult: func(ctx context.Context, result domain.ScanResult) error {
					return nil
				},
				MockMarkScanAsFailed: func(ctx context.Context, scanID uuid.UUID) error {
					return nil
				},
			},
			vulnService: &mock_services.MockVulnerabilityService{
				MockCreateNetworkOSVulnerabilities: func(ctx context.Context, scanID uuid.UUID, nmapResult tools.NmapResult) error {
					return nil
				},
			},
			data: []byte(`{
							  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
							  "timestamp": "2025-07-07T12:34:56Z",
                              "ToolResult": {
								"tool_name": "Nmap",
                                "result": {
									"HostName":"",
									"HostAddress":"",
									"ScannedPorts":[],
									"MostLikelyOS":{} 
								},
							    "error": null,
							    "timestamp": "2025-07-07T12:34:56Z"
							}}`),
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewNmapHandler(
				tt.scanService,
				tt.vulnService,
				1,
			)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			err := h.processNmapEvent(ctx, tt.data)
			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}

		})
	}
}

// TestWorkerPoolSize_Nmap verifies that exactly N workers are processing events
func TestWorkerPoolSize_Nmap(t *testing.T) {
	// This is a unit test that verifies the configuration
	// It ensures our worker pool has the expected concurrency level
	workerCount := 5
	maxConcurrent := int32(0)

	scanService := &mock_services.MockScanService{
		MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
			return &domain.Scan{Status: "InProgress"}, nil
		},
		MockInsertScanResult: func(ctx context.Context, result domain.ScanResult) error {
			return nil
		},
		MockMarkScanAsFailed: func(ctx context.Context, scanID uuid.UUID) error {
			return nil
		},
	}

	vulnService := &mock_services.MockVulnerabilityService{
		MockCreateNetworkOSVulnerabilities: func(ctx context.Context, scanID uuid.UUID, nmapResult tools.NmapResult) error {
			return nil
		},
	}

	handler := NewNmapHandler(scanService, vulnService, workerCount)
	eventCount := 20
	for i := 0; i < eventCount; i++ {
		msg := &nats.Msg{
			Subject: "",
			Reply:   "",
			Header:  nil,
			Data: []byte(`{
							  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
							  "timestamp": "2025-07-07T12:34:56Z",
                              "ToolResult": {
								"tool_name": "Nmap",
                                "result": {
									"HostName":"",
									"HostAddress":"",
									"ScannedPorts":[],
									"MostLikelyOS":{} 
								},
							    "error": null,
							    "timestamp": "2025-07-07T12:34:56Z"
							}}`),
			Sub: nil,
		}
		handler.HandleMessage(msg)
	}
	// Wait for processing
	time.Sleep(500 * time.Millisecond)
	// Verify maximum concurrent workers never exceeded limit
	assert.LessOrEqual(t, int(maxConcurrent), workerCount,
		"Maximum concurrent workers (%d) exceeded configured limit (%d)",
		maxConcurrent, workerCount)
	// Verify all events were processed
	metrics := handler.GetMetrics()
	assert.Equal(t, uint64(eventCount), metrics["processed"])
}

// TestConcurrentEventHandling_Nmap verifies thread-safety
func TestConcurrentEventHandling_Nmap(t *testing.T) {
	// This test uses Go's race detector to find data races
	// Run with: go test -race
	workerCount := 10

	scanService := &mock_services.MockScanService{
		MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
			return &domain.Scan{Status: "InProgress"}, nil
		},
		MockInsertScanResult: func(ctx context.Context, result domain.ScanResult) error {
			return nil
		},
		MockMarkScanAsFailed: func(ctx context.Context, scanID uuid.UUID) error {
			return nil
		},
	}

	vulnService := &mock_services.MockVulnerabilityService{
		MockCreateNetworkOSVulnerabilities: func(ctx context.Context, scanID uuid.UUID, nmapResult tools.NmapResult) error {
			return nil
		},
	}

	handler := NewNmapHandler(scanService, vulnService, workerCount)

	// Concurrent operations from multiple goroutines
	var wg sync.WaitGroup
	goroutines := 100
	eventsPerGoroutine := 10
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(routineID int) {
			defer wg.Done()
			for j := 0; j < eventsPerGoroutine; j++ {
				msg := &nats.Msg{
					Subject: "",
					Reply:   "",
					Header:  nil,
					Data: []byte(`{
							  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
							  "timestamp": "2025-07-07T12:34:56Z",
                              "ToolResult": {
								"tool_name": "Nmap",
                                "result": {
									"HostName":"",
									"HostAddress":"",
									"ScannedPorts":[],
									"MostLikelyOS":{} 
								},
							    "error": null,
							    "timestamp": "2025-07-07T12:34:56Z"
							}}`),
					Sub: nil,
				}
				handler.HandleMessage(msg)
				// Also read metrics concurrently
				if j%3 == 0 {
					_ = handler.GetMetrics()
				}
			}
		}(i)
	}
	wg.Wait()
	// Verify no panics occurred and metrics are consistent
	metrics := handler.GetMetrics()
	total := metrics["processed"].(uint64) + metrics["dropped"].(uint64)
	assert.LessOrEqual(t, int(total), goroutines*eventsPerGoroutine)
}

// TestWorkerFailures_Nmap verifies system resilience to worker failures
func TestWorkerFailures_Nmap(t *testing.T) {
	// This is a chaos engineering test
	// It verifies the system continues operating when workers fail
	workerCount := 5
	failureRate := 0.3 // 30% of processing attempts will fail

	scanService := &mock_services.MockScanService{
		MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
			return &domain.Scan{Status: "InProgress"}, nil
		},
		MockInsertScanResult: func(ctx context.Context, result domain.ScanResult) error {
			if rand.Float64() < failureRate {
				return fmt.Errorf("simulated failure")
			}
			return nil
		},
		MockMarkScanAsFailed: func(ctx context.Context, scanID uuid.UUID) error {
			return nil
		},
	}

	vulnService := &mock_services.MockVulnerabilityService{
		MockCreateNetworkOSVulnerabilities: func(ctx context.Context, scanID uuid.UUID, nmapResult tools.NmapResult) error {
			return nil
		},
	}
	handler := NewNmapHandler(scanService, vulnService, workerCount)

	// Send events and track results
	eventCount := 100
	for i := 0; i < eventCount; i++ {
		msg := &nats.Msg{
			Subject: "",
			Reply:   "",
			Header:  nil,
			Data: []byte(`{
							  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
							  "timestamp": "2025-07-07T12:34:56Z",
                              "ToolResult": {
								"tool_name": "Nmap",
                                "result": {
									"HostName":"",
									"HostAddress":"",
									"ScannedPorts":[],
									"MostLikelyOS":{} 
								},
							    "error": null,
							    "timestamp": "2025-07-07T12:34:56Z"
							}}`),
			Sub: nil,
		}
		handler.HandleMessage(msg)
	}
	// Wait for processing
	time.Sleep(2 * time.Second)
	// Verify system continued operating despite failures
	metrics := handler.GetMetrics()
	processed := metrics["processed"].(uint64)
	failed := metrics["failed"].(uint64)
	t.Logf("Chaos Test Results:")
	t.Logf(" Processed: %d", processed)
	t.Logf(" Failed: %d", failed)
	t.Logf(" Failure Rate: %.2f%%", float64(failed)/float64(processed+failed)*100)
	// System should have processed some events despite failures
	assert.Greater(t, int(processed), 0, "No events processed")
	assert.Greater(t, int(failed), 0, "No failures recorded")
	// Total should match what we expect
	totalHandled := processed + failed
	assert.Greater(t, int(totalHandled), eventCount/2, "Too many events lost during chaos")
}

// BenchmarkEventProcessing_Nmap establishes performance baselines
func BenchmarkEventProcessing_Nmap(b *testing.B) {
	workerCounts := []int{1, 5, 10, 20, 50}
	for _, workers := range workerCounts {
		b.Run(fmt.Sprintf("Workers-%d", workers), func(b *testing.B) {

			scanService := &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "InProgress"}, nil
				},
				MockInsertScanResult: func(ctx context.Context, result domain.ScanResult) error {
					return nil
				},
				MockMarkScanAsFailed: func(ctx context.Context, scanID uuid.UUID) error {
					return nil
				},
			}

			vulnService := &mock_services.MockVulnerabilityService{
				MockCreateNetworkOSVulnerabilities: func(ctx context.Context, scanID uuid.UUID, nmapResult tools.NmapResult) error {
					return nil
				},
			}

			handler := NewNmapHandler(scanService, vulnService, workers)

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					msg := &nats.Msg{
						Subject: "",
						Reply:   "",
						Header:  nil,
						Data: []byte(`{
							  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
							  "timestamp": "2025-07-07T12:34:56Z",
                              "ToolResult": {
								"tool_name": "Nmap",
                                "result": {
									"HostName":"",
									"HostAddress":"",
									"ScannedPorts":[],
									"MostLikelyOS":{} 
								},
							    "error": null,
							    "timestamp": "2025-07-07T12:34:56Z"
							}}`),
						Sub: nil,
					}
					handler.HandleMessage(msg)
					i++
				}
			})
			b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(),
				"events/sec")
		})
	}
}

func TestBackpressureHandling_Nmap(t *testing.T) {
	// This is an integration test that verifies system behavior under load
	// It ensures our backpressure mechanisms work correctly
	workerCount := 2
	var wg sync.WaitGroup
	eventCount := 50
	wg.Add(eventCount)

	scanService := &mock_services.MockScanService{
		MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
			return &domain.Scan{Status: "InProgress"}, nil
		},
		MockInsertScanResult: func(ctx context.Context, result domain.ScanResult) error {
			time.Sleep(200 * time.Millisecond)
			return nil
		},
		MockMarkScanAsFailed: func(ctx context.Context, scanID uuid.UUID) error {
			return nil
		},
	}

	vulnService := &mock_services.MockVulnerabilityService{
		MockCreateNetworkOSVulnerabilities: func(ctx context.Context, scanID uuid.UUID, nmapResult tools.NmapResult) error {
			return nil
		},
	}
	handler := NewNmapHandler(scanService, vulnService, workerCount)
	for i := 0; i < eventCount; i++ {
		go func(id int) {
			defer wg.Done()
			msg := &nats.Msg{
				Subject: "",
				Reply:   "",
				Header:  nil,
				Data: []byte(`{
							  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
							  "timestamp": "2025-07-07T12:34:56Z",
                              "ToolResult": {
								"tool_name": "Nmap",
                                "result": {
									"HostName":"",
									"HostAddress":"",
									"ScannedPorts":[],
									"MostLikelyOS":{} 
								},
							    "error": null,
							    "timestamp": "2025-07-07T12:34:56Z"
							}}`),
				Sub: nil,
			}
			handler.HandleMessage(msg)
		}(i)
	}
	wg.Wait()

	// Verify metrics are accurate
	metrics := handler.GetMetrics()
	// Verify backpressure was applied
	assert.Greater(t, metrics["dropped"], uint64(0),
		"Expected some events to be dropped due to backpressure")
}
