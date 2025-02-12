package storage

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestPostgreSQLStore_buildSeverityWhereClause(t *testing.T) {
	tests := []struct {
		name            string
		severityFilters []string
		queryParams     []any
		wantQuery       string
		wantParams      []any
	}{
		{
			name:            "No severity filters or query params",
			severityFilters: []string{},
			queryParams:     []any{},
			wantQuery:       "",
			wantParams:      []any{},
		},
		{
			name:            "Single severity filter",
			severityFilters: []string{"critical"},
			queryParams:     []any{},
			wantQuery:       "AND sv.severity ILIKE ANY(array[$1])",
			wantParams:      []any{"critical"},
		},
		{
			name:            "Multiple severity filters",
			severityFilters: []string{"critical", "high"},
			queryParams:     []any{},
			wantQuery:       "AND sv.severity ILIKE ANY(array[$1,$2])",
			wantParams:      []any{"critical", "high"},
		},
		{
			name:            "Two severity Filters and two query Params",
			severityFilters: []string{"critical", "high"},
			queryParams: []any{
				uuid.MustParse("515a7031-af4e-4661-9c18-603da9931db8"),
				"Month",
			},
			wantQuery: "AND sv.severity ILIKE ANY(array[$3,$4])",
			wantParams: []any{
				uuid.MustParse("515a7031-af4e-4661-9c18-603da9931db8"),
				"Month",
				"critical",
				"high",
			},
		},
		{
			name:            "Multiple severity filters with special characters",
			severityFilters: []string{"CRITICAL", "higH"},
			queryParams:     []any{},
			wantQuery:       "AND sv.severity ILIKE ANY(array[$1,$2])",
			wantParams:      []any{"CRITICAL", "higH"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock
			s := &PostgreSQLStore{}

			gotQuery, gotParams := s.buildSeverityWhereClause(tt.severityFilters, tt.queryParams)
			if gotQuery != tt.wantQuery {
				t.Errorf("buildSeverityWhereClause() = %v, want %v", gotQuery, tt.wantQuery)
			}
			if !reflect.DeepEqual(gotParams, tt.wantParams) {
				t.Errorf("buildSeverityWhereClause() = %v, want %v", gotParams, tt.wantParams)
			}
		})
	}
}
