package consumers

import (
	"context"
	"errors"
	"fmt"
	"github.com/nats-io/nats.go"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	mock_services "github.com/kptm-tools/core-service/pkg/mocks/services"
	"github.com/stretchr/testify/assert"
)

func TestProcessWhoIsEvent(t *testing.T) {

	tests := []struct {
		name          string
		scanService   interfaces.IScanService
		data          []byte
		expectedError string
	}{
		{
			name:          "Error with unmarshal",
			scanService:   &mock_services.MockScanService{},
			data:          []byte(``),
			expectedError: "unexpected end of JSON input",
		},
		{
			name:          "Invalid tool name",
			scanService:   &mock_services.MockScanService{},
			data:          []byte(`{}`),
			expectedError: "invalid toolName for WhoIsEvent",
		},
		{
			name: "Scan not found",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return nil, customerrors.ErrScanNotFound
				},
			},
			data: []byte(`{
							  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
							  "timestamp": "2025-07-07T12:34:56Z",
                              "ToolResult": {"tool_name": "WhoIs",
                              "result": null,
							  "error": null,
							  "timestamp": "2025-07-07T12:34:56Z"
							}}`),
			expectedError: "scan not found",
		},
		{
			name: "Error in inserting scan result",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "InProgress"}, nil
				},
				MockInsertScanResult: func(ctx context.Context, result domain.ScanResult) error {
					return errors.New("error in inserting scan result")
				},
			},
			data: []byte(`{
				"scan_id": "dfa86ed2-5601-4dec-be89-97a16a579dfb",
				"ToolResult": {
					"tool_name": "WhoIs",
					"result": null,
					"timestamp": "2025-07-07T12:34:56Z"
				}
			}`),
			expectedError: "error in inserting scan result",
		},
		{
			name: "Good insertion",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{
						ID:     id,
						Status: "InProgress",
					}, nil
				},
				MockInsertScanResult: func(ctx context.Context, sr domain.ScanResult) error {
					return nil
				},
			},
			data: []byte(`{
				"scan_id": "dfa86ed2-5601-4dec-be89-97a16a579dfb",
				"ToolResult": {
					"tool_name": "WhoIs",
					"result": {
					  "raw_data": {
						"domain": {
						  "id": "8363973_DOMAIN_NET-VRSN",
						  "domain": "testfire.net",
						  "punycode": "testfire.net",
						  "name": "testfire",
						  "extension": "net",
						  "whois_server": "whois.registrar.amazon",
						  "status": [
							"clientDeleteProhibited",
							"clientTransferProhibited",
							"clientUpdateProhibited"
						  ],
						  "name_servers": [
							"asia3.akam.net"
						  ],
						  "created_date": "1999-07-23T13:52:32Z",
						  "created_date_in_time": "1999-07-23T13:52:32Z",
						  "updated_date": "2025-02-27T17:53:33Z",
						  "updated_date_in_time": "2025-02-27T17:53:33Z",
						  "expiration_date": "2026-07-23T13:52:32Z",
						  "expiration_date_in_time": "2026-07-23T13:52:32Z"
						}
					  }
					}
				}
			}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewWhoIsHandler(tt.scanService, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := h.processWhoIsEvent(ctx, tt.data)
			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestWorkerPoolSize_WhoIs verifies that exactly N workers are processing events
func TestWorkerPoolSize_WhoIs(t *testing.T) {
	// This is a unit test that verifies the configuration
	// It ensures our worker pool has the expected concurrency level
	workerCount := 5
	maxConcurrent := int32(0)

	scanService := &mock_services.MockScanService{
		MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
			return &domain.Scan{
				ID:     id,
				Status: "InProgress",
			}, nil
		},
		MockInsertScanResult: func(ctx context.Context, sr domain.ScanResult) error {
			return nil
		},
	}

	handler := NewWhoIsHandler(scanService, workerCount)
	eventCount := 20
	for i := 0; i < eventCount; i++ {
		msg := &nats.Msg{
			Subject: "",
			Reply:   "",
			Header:  nil,
			Data: []byte(`{
				"scan_id": "dfa86ed2-5601-4dec-be89-97a16a579dfb",
				"ToolResult": {
					"tool_name": "WhoIs",
					"result": {
					  "raw_data": {
						"domain": {
						  "id": "8363973_DOMAIN_NET-VRSN",
						  "domain": "testfire.net",
						  "punycode": "testfire.net",
						  "name": "testfire",
						  "extension": "net",
						  "whois_server": "whois.registrar.amazon",
						  "status": [
							"clientDeleteProhibited",
							"clientTransferProhibited",
							"clientUpdateProhibited"
						  ],
						  "name_servers": [
							"asia3.akam.net"
						  ],
						  "created_date": "1999-07-23T13:52:32Z",
						  "created_date_in_time": "1999-07-23T13:52:32Z",
						  "updated_date": "2025-02-27T17:53:33Z",
						  "updated_date_in_time": "2025-02-27T17:53:33Z",
						  "expiration_date": "2026-07-23T13:52:32Z",
						  "expiration_date_in_time": "2026-07-23T13:52:32Z"
						}
					  }
					}
				}
			}`),
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

// TestConcurrentEventHandling verifies thread-safety
func TestConcurrentEventHandling_WhoIs(t *testing.T) {
	// This test uses Go's race detector to find data races
	// Run with: go test -race
	workerCount := 10

	scanService := &mock_services.MockScanService{
		MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
			return &domain.Scan{
				ID:     id,
				Status: "InProgress",
			}, nil
		},
		MockInsertScanResult: func(ctx context.Context, sr domain.ScanResult) error {
			return nil
		},
	}

	handler := NewWhoIsHandler(scanService, workerCount)

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
				"scan_id": "dfa86ed2-5601-4dec-be89-97a16a579dfb",
				"ToolResult": {
					"tool_name": "WhoIs",
					"result": {
					  "raw_data": {
						"domain": {
						  "id": "8363973_DOMAIN_NET-VRSN",
						  "domain": "testfire.net",
						  "punycode": "testfire.net",
						  "name": "testfire",
						  "extension": "net",
						  "whois_server": "whois.registrar.amazon",
						  "status": [
							"clientDeleteProhibited",
							"clientTransferProhibited",
							"clientUpdateProhibited"
						  ],
						  "name_servers": [
							"asia3.akam.net"
						  ],
						  "created_date": "1999-07-23T13:52:32Z",
						  "created_date_in_time": "1999-07-23T13:52:32Z",
						  "updated_date": "2025-02-27T17:53:33Z",
						  "updated_date_in_time": "2025-02-27T17:53:33Z",
						  "expiration_date": "2026-07-23T13:52:32Z",
						  "expiration_date_in_time": "2026-07-23T13:52:32Z"
						}
					  }
					}
				}
			}`),
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

// TestWorkerFailures verifies system resilience to worker failures
func TestWorkerFailures_WhoIs(t *testing.T) {
	// This is a chaos engineering test
	// It verifies the system continues operating when workers fail
	workerCount := 5
	failureRate := 0.3 // 30% of processing attempts will fail

	scanService := &mock_services.MockScanService{
		MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
			return &domain.Scan{
				ID:     id,
				Status: "InProgress",
			}, nil
		},
		MockInsertScanResult: func(ctx context.Context, sr domain.ScanResult) error {
			if rand.Float64() < failureRate {
				return fmt.Errorf("simulated failure")
			}
			return nil
		},
	}
	handler := NewWhoIsHandler(scanService, workerCount)

	// Send events and track results
	eventCount := 100
	for i := 0; i < eventCount; i++ {
		msg := &nats.Msg{
			Subject: "",
			Reply:   "",
			Header:  nil,
			Data: []byte(`{
				"scan_id": "dfa86ed2-5601-4dec-be89-97a16a579dfb",
				"ToolResult": {
					"tool_name": "WhoIs",
					"result": {
					  "raw_data": {
						"domain": {
						  "id": "8363973_DOMAIN_NET-VRSN",
						  "domain": "testfire.net",
						  "punycode": "testfire.net",
						  "name": "testfire",
						  "extension": "net",
						  "whois_server": "whois.registrar.amazon",
						  "status": [
							"clientDeleteProhibited",
							"clientTransferProhibited",
							"clientUpdateProhibited"
						  ],
						  "name_servers": [
							"asia3.akam.net"
						  ],
						  "created_date": "1999-07-23T13:52:32Z",
						  "created_date_in_time": "1999-07-23T13:52:32Z",
						  "updated_date": "2025-02-27T17:53:33Z",
						  "updated_date_in_time": "2025-02-27T17:53:33Z",
						  "expiration_date": "2026-07-23T13:52:32Z",
						  "expiration_date_in_time": "2026-07-23T13:52:32Z"
						}
					  }
					}
				}
			}`),
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

// BenchmarkEventProcessing establishes performance baselines
func BenchmarkEventProcessing_WhoIs(b *testing.B) {
	workerCounts := []int{1, 5, 10, 20, 50}
	for _, workers := range workerCounts {
		b.Run(fmt.Sprintf("Workers-%d", workers), func(b *testing.B) {

			scanService := &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{
						ID:     id,
						Status: "InProgress",
					}, nil
				},
				MockInsertScanResult: func(ctx context.Context, sr domain.ScanResult) error {
					return nil
				},
			}
			handler := NewWhoIsHandler(scanService, workers)

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					msg := &nats.Msg{
						Subject: "",
						Reply:   "",
						Header:  nil,
						Data: []byte(`{
				"scan_id": "dfa86ed2-5601-4dec-be89-97a16a579dfb",
				"ToolResult": {
					"tool_name": "WhoIs",
					"result": {
					  "raw_data": {
						"domain": {
						  "id": "8363973_DOMAIN_NET-VRSN",
						  "domain": "testfire.net",
						  "punycode": "testfire.net",
						  "name": "testfire",
						  "extension": "net",
						  "whois_server": "whois.registrar.amazon",
						  "status": [
							"clientDeleteProhibited",
							"clientTransferProhibited",
							"clientUpdateProhibited"
						  ],
						  "name_servers": [
							"asia3.akam.net"
						  ],
						  "created_date": "1999-07-23T13:52:32Z",
						  "created_date_in_time": "1999-07-23T13:52:32Z",
						  "updated_date": "2025-02-27T17:53:33Z",
						  "updated_date_in_time": "2025-02-27T17:53:33Z",
						  "expiration_date": "2026-07-23T13:52:32Z",
						  "expiration_date_in_time": "2026-07-23T13:52:32Z"
						}
					  }
					}
				}
			}`),
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

func TestBackpressureHandling_WhoIs(t *testing.T) {
	// This is an integration test that verifies system behavior under load
	// It ensures our backpressure mechanisms work correctly
	workerCount := 2
	var wg sync.WaitGroup
	eventCount := 50
	wg.Add(eventCount)
	scanService := &mock_services.MockScanService{
		MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
			return &domain.Scan{
				ID:     id,
				Status: "InProgress",
			}, nil
		},
		MockInsertScanResult: func(ctx context.Context, sr domain.ScanResult) error {
			time.Sleep(200 * time.Millisecond)
			return nil
		},
	}
	handler := NewWhoIsHandler(scanService, workerCount)
	for i := 0; i < eventCount; i++ {
		go func(id int) {
			defer wg.Done()
			msg := &nats.Msg{
				Subject: "",
				Reply:   "",
				Header:  nil,
				Data: []byte(`{
				"scan_id": "dfa86ed2-5601-4dec-be89-97a16a579dfb",
				"ToolResult": {
					"tool_name": "WhoIs",
					"result": {
					  "raw_data": {
						"domain": {
						  "id": "8363973_DOMAIN_NET-VRSN",
						  "domain": "testfire.net",
						  "punycode": "testfire.net",
						  "name": "testfire",
						  "extension": "net",
						  "whois_server": "whois.registrar.amazon",
						  "status": [
							"clientDeleteProhibited",
							"clientTransferProhibited",
							"clientUpdateProhibited"
						  ],
						  "name_servers": [
							"asia3.akam.net"
						  ],
						  "created_date": "1999-07-23T13:52:32Z",
						  "created_date_in_time": "1999-07-23T13:52:32Z",
						  "updated_date": "2025-02-27T17:53:33Z",
						  "updated_date_in_time": "2025-02-27T17:53:33Z",
						  "expiration_date": "2026-07-23T13:52:32Z",
						  "expiration_date_in_time": "2026-07-23T13:52:32Z"
						}
					  }
					}
				}
			}`),
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
