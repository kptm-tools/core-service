package consumers

import (
	"context"
	"errors"
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
			expectedError: "error inserting ScanResult to DB of Scan Status",
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
