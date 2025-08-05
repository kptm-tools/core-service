package consumers

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/events"
	"github.com/nats-io/nats.go"
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

func TestProcessDNSLookupEvent(t *testing.T) {
	tests := []struct {
		name          string
		scanService   interfaces.IScanService
		data          []byte
		expectedError string
	}{
		{
			name:          "Invalid JSON",
			scanService:   &mock_services.MockScanService{},
			data:          []byte(``),
			expectedError: "unexpected end of JSON input",
		},
		{
			name:          "Invalid tool name",
			scanService:   &mock_services.MockScanService{},
			data:          []byte(`{}`),
			expectedError: "invalid toolName for DNSLookupEvent",
		},
		{
			name: "Scan not found",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return nil, customerrors.ErrScanNotFound
				},
			},
			data: []byte(`{
				"scan_id": "dfa86ed2-5601-4dec-be89-97a16a579dfb",
				"ToolResult": {
					"tool_name": "DNSLookup",
					"result": null
				}
			}`),
			expectedError: "scan not found",
		},
		{
			name: "Scan is failed or cancelled",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{
						ID:     id,
						Status: "Failed",
					}, nil
				},
			},
			data: []byte(`{
				"scan_id": "dfa86ed2-5601-4dec-be89-97a16a579dfb",
				"ToolResult": {
					"tool_name": "DNSLookup",
					"result": null
				}
			}`),
			expectedError: "cannot insert scan result: scan is failed or cancelled",
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
					"tool_name": "DNSLookup",
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
					"tool_name": "DNSLookup",
					"result": {
					  "domain": "testfire.net",
					  "dns_records": [
						{
						  "type": "A",
						  "name": "testfire.net.",
						  "ttl": 21600,
						  "value": "65.61.137.117"
						}
					  ],
					  "dnssec_enabled": false,
					  "lookup_duration": 1496295752,
					  "created_at": "2025-07-31T17:34:39.109806531Z",
					  "timestamp": "2025-07-31T17:34:37.613510237Z",
					  "whois_results": {
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
							  "updated_date": "2025-02-27T17:53:33Z",
							  "expiration_date": "2026-07-23T13:52:32Z"
							},
							"registrar": {
							  "id": "468",
							  "name": "Amazon Registrar, Inc.",
							  "phone": "+1.2024422253",
							  "email": "trustandsafety@support.aws.com",
							  "referral_url": "https://registrar.amazon.com"
							},
							"registrant": {
							  "id": "Not Available From Registry",
							  "name": "On behalf of testfire.net owner",
							  "organization": "Identity Protection Service",
							  "street": "PO Box 786",
							  "city": "Hayes",
							  "province": "Middlesex",
							  "postal_code": "UB3 9TR",
							  "country": "GB",
							  "phone": "+44.1483307527",
							  "fax": "+44.1483304031",
							  "email": "ff33a434-8474-412e-b6f2-2e6b503c99fb@identity-protect.org"
							},
							"technical": {
							  "id": "Not Available From Registry",
							  "name": "On behalf of testfire.net owner",
							  "organization": "Identity Protection Service",
							  "street": "PO Box 786",
							  "city": "Hayes",
							  "province": "Middlesex",
							  "postal_code": "UB3 9TR",
							  "country": "GB",
							  "phone": "+44.1483307527",
							  "fax": "+44.1483304031",
							  "email": "ff33a434-8474-412e-b6f2-2e6b503c99fb@identity-protect.org"
							}
						  }
						}
					  }
					}
				}
			}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewDNSLookupHandler(tt.scanService)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := h.processDNSLookupEvent(ctx, tt.data)

			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProcessDNSLookupEvent_UnitCases(t *testing.T) {
	validScanID := uuid.New()
	validEvent := events.ToolResultEvent{
		ScanID: validScanID,
		ToolResult: events.ToolResult{
			Tool: enums.ToolDNSLookup,
			Result: map[string]interface{}{
				"domain": "example.com",
			},
		},
	}
	validData, _ := json.Marshal(validEvent)

	t.Run("invalid JSON", func(t *testing.T) {
		h := NewDNSLookupHandler(&mock_services.MockScanService{}, 1)
		err := h.processDNSLookupEvent(context.Background(), []byte("{invalid"))
		assert.Error(t, err)
	})

	t.Run("invalid tool name", func(t *testing.T) {
		evt := validEvent
		evt.ToolResult.Tool = enums.ToolNmap
		data, _ := json.Marshal(evt)
		h := NewDNSLookupHandler(&mock_services.MockScanService{}, 1)
		err := h.processDNSLookupEvent(context.Background(), data)
		assert.EqualError(t, err, "invalid toolName for DNSLookupEvent")
	})

	t.Run("scan not found", func(t *testing.T) {
		h := NewDNSLookupHandler(&mock_services.MockScanService{
			MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
				return nil, errors.New("scan not found")
			},
		}, 1)
		err := h.processDNSLookupEvent(context.Background(), validData)
		assert.EqualError(t, err, "scan not found")
	})

	t.Run("scan is failed or cancelled", func(t *testing.T) {
		h := NewDNSLookupHandler(&mock_services.MockScanService{
			MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
				return &domain.Scan{ID: id, Status: "Failed"}, nil
			},
		}, 1)
		err := h.processDNSLookupEvent(context.Background(), validData)
		assert.EqualError(t, err, "cannot insert scan result: scan is failed or cancelled")
	})

	t.Run("error inserting scan result", func(t *testing.T) {
		h := NewDNSLookupHandler(&mock_services.MockScanService{
			MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
				return &domain.Scan{ID: id, Status: "InProgress"}, nil
			},
			MockInsertScanResult: func(ctx context.Context, result domain.ScanResult) error {
				return errors.New("db error")
			},
		}, 1)
		err := h.processDNSLookupEvent(context.Background(), validData)
		assert.EqualError(t, err, "db error")
	})

	t.Run("success", func(t *testing.T) {
		h := NewDNSLookupHandler(&mock_services.MockScanService{
			MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
				return &domain.Scan{ID: id, Status: "InProgress"}, nil
			},
			MockInsertScanResult: func(ctx context.Context, result domain.ScanResult) error {
				return nil
			},
		}, 1)
		err := h.processDNSLookupEvent(context.Background(), validData)
		assert.NoError(t, err)
	})
}

func TestDNSLookupHandler_WorkerPool(t *testing.T) {
	var (
		mu         sync.Mutex
		calls      []uuid.UUID
		workerNum  = 3
		messageNum = 10
	)
	mockScanService := &mock_services.MockScanService{
		MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
			return &domain.Scan{ID: id, Status: "InProgress"}, nil
		},
		MockInsertScanResult: func(ctx context.Context, result domain.ScanResult) error {
			mu.Lock()
			calls = append(calls, result.ScanID)
			mu.Unlock()
			return nil
		},
	}
	handler := NewDNSLookupHandler(mockScanService, workerNum)

	for i := 0; i < messageNum; i++ {
		scanID := uuid.New()
		evt := events.ToolResultEvent{
			ScanID: scanID,
			ToolResult: events.ToolResult{
				Tool: enums.ToolDNSLookup,
				Result: map[string]interface{}{
					"domain": "example.com",
				},
			},
		}
		data, _ := json.Marshal(evt)
		msg := &nats.Msg{Data: data}
		handler.HandleMessage(msg)
	}

	// Wait for all messages to be processed
	time.Sleep(1 * time.Second)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, messageNum, len(calls))
}
