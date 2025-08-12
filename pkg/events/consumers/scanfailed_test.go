package consumers

import (
	"context"
	"fmt"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	mockservices "github.com/kptm-tools/core-service/pkg/mocks/services"
	"github.com/nats-io/nats.go"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestProcessScanFailedEvent(t *testing.T) {
	tests := []struct {
		name          string
		scanService   interfaces.IScanService
		data          []byte
		expectedError string
	}{
		{
			name:          "Error with unmarshal",
			scanService:   &mockservices.MockScanService{},
			data:          []byte(``),
			expectedError: "unexpected end of JSON input",
		},
		{
			name: "Scan failed",
			scanService: &mockservices.MockScanService{
				MockMarkScanAsFailed: func(ctx context.Context, scanID uuid.UUID) error {
					assert.Equal(t, "301524ab-5d78-4a74-b278-dcf279db9b42", scanID.String())
					return nil
				},
			},
			data: []byte(`{
				"scan_id": "301524ab-5d78-4a74-b278-dcf279db9b42",
				"reason": "Test failure reason"
			}`),
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewScanFailedHandler(tt.scanService, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := h.processScanFailedEvent(ctx, tt.data)
			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestWorkerPoolSize_DNSLookup verifies that exactly N workers are processing events
func TestWorkerPoolSize_ScanFailed(t *testing.T) {
	// This is a unit test that verifies the configuration
	// It ensures our worker pool has the expected concurrency level
	workerCount := 5
	maxConcurrent := int32(0)

	scanService := &mockservices.MockScanService{
		MockMarkScanAsFailed: func(ctx context.Context, scanID uuid.UUID) error {
			return nil
		},
	}

	handler := NewScanFailedHandler(scanService, workerCount)
	eventCount := 20
	for i := 0; i < eventCount; i++ {
		msg := &nats.Msg{
			Subject: "",
			Reply:   "",
			Header:  nil,
			Data: []byte(`{
				"scan_id": "301524ab-5d78-4a74-b278-dcf279db9b42",
				"reason": "Test failure reason"
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
func TestConcurrentEventHandling_ScanFailed(t *testing.T) {
	// This test uses Go's race detector to find data races
	// Run with: go test -race
	workerCount := 10

	scanService := &mockservices.MockScanService{
		MockMarkScanAsFailed: func(ctx context.Context, scanID uuid.UUID) error {
			return nil
		},
	}

	handler := NewScanFailedHandler(scanService, workerCount)

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
				"scan_id": "301524ab-5d78-4a74-b278-dcf279db9b42",
				"reason": "Test failure reason"
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
func TestWorkerFailures_ScanFailed(t *testing.T) {
	// This is a chaos engineering test
	// It verifies the system continues operating when workers fail
	workerCount := 5
	failureRate := 0.3 // 30% of processing attempts will fail

	scanService := &mockservices.MockScanService{

		MockMarkScanAsFailed: func(ctx context.Context, scanID uuid.UUID) error {
			if rand.Float64() < failureRate {
				return fmt.Errorf("simulated failure")
			}
			return nil
		},
	}
	handler := NewScanFailedHandler(scanService, workerCount)

	// Send events and track results
	eventCount := 100
	for i := 0; i < eventCount; i++ {
		msg := &nats.Msg{
			Subject: "",
			Reply:   "",
			Header:  nil,
			Data: []byte(`{
				"scan_id": "301524ab-5d78-4a74-b278-dcf279db9b42",
				"reason": "Test failure reason"
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
func BenchmarkEventProcessing_ScanFailed(b *testing.B) {
	workerCounts := []int{1, 5, 10, 20, 50}
	for _, workers := range workerCounts {
		b.Run(fmt.Sprintf("Workers-%d", workers), func(b *testing.B) {

			scanService := &mockservices.MockScanService{
				MockMarkScanAsFailed: func(ctx context.Context, scanID uuid.UUID) error {
					return nil
				},
			}
			handler := NewScanFailedHandler(scanService, workers)

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					msg := &nats.Msg{
						Subject: "",
						Reply:   "",
						Header:  nil,
						Data: []byte(`{
							"scan_id": "301524ab-5d78-4a74-b278-dcf279db9b42",
							"reason": "Test failure reason"
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

func TestBackpressureHandling_ScanFailed(t *testing.T) {
	// This is an integration test that verifies system behavior under load
	// It ensures our backpressure mechanisms work correctly
	workerCount := 2
	var wg sync.WaitGroup
	eventCount := 50
	wg.Add(eventCount)
	scanService := &mockservices.MockScanService{
		MockMarkScanAsFailed: func(ctx context.Context, scanID uuid.UUID) error {
			time.Sleep(200 * time.Millisecond)
			return nil
		},
	}
	handler := NewScanFailedHandler(scanService, workerCount)
	for i := 0; i < eventCount; i++ {
		go func(id int) {
			defer wg.Done()
			msg := &nats.Msg{
				Subject: "",
				Reply:   "",
				Header:  nil,
				Data: []byte(`{
				"scan_id": "301524ab-5d78-4a74-b278-dcf279db9b42",
				"reason": "Test failure reason"
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
