# Jira Task: Integrate NetworkOSVulnerabilityDetails Throughout Application Stack

## Task Summary
**Title**: Refactor Vulnerability API Layer to Use NetworkOSVulnerabilityDetails Domain Model

**Story Points**: 8

**Sprint**: Current Sprint

**Type**: Technical Improvement / Refactoring

---

## Description

The domain layer has been successfully refactored to use the new `NetworkOSVulnerabilityDetails` domain model, which provides clean separation of concerns between CVE, CWE, and vulnerability data while using database-driven OWASP Top 10 categories instead of runtime mapping. However, the application layer (handlers, services, and interfaces) still uses the legacy `tools.Vulnerability` and `domain.ScanVulnerabilityDetail` approaches.

This task involves integrating the new `NetworkOSVulnerabilityDetails` domain model throughout the entire application stack to ensure consistency, maintainability, and proper use of database-driven OWASP categories.

**Current State:**
- ✅ Domain model `NetworkOSVulnerabilityDetails` is implemented and tested
- ✅ Storage layer supports the new model via `parseNetworkOSVulnerabilityWithDetails`
- ✅ Database schema includes `owasp_top10_category` field in `cwe_details` table
- ❌ Handlers still use `domain.ScanVulnerabilityDetail` 
- ❌ Services still return legacy domain models
- ❌ Repository interfaces return mixed model types

**Target State:**
- All vulnerability endpoints return NetworkOSVulnerability data
- Services use NetworkOSVulnerabilityDetails internally
- Clean API responses with proper OWASP categorization
- Consistent domain model usage across all layers

---

## Acceptance Criteria

### AC1: Update Vulnerability Service Interface and Implementation
- [ ] Update `IVulnerabilityService.GetScanVulnerabilityDetail` to return `*NetworkOSVulnerabilityDetails` instead of `*domain.ScanVulnerabilityDetail`
- [ ] Refactor `VulnerabilityService.GetScanVulnerabilityDetail` method to use new domain model
- [ ] Remove complex domain object construction logic and leverage NetworkOSVulnerabilityDetails methods
- [ ] Ensure all vulnerability retrieval methods consistently use NetworkOSVulnerabilityDetails

### AC2: Update Vulnerability Repository Interface
- [ ] Update `VulnerabilityRepository.GetVulnerabilityByID` to return `*NetworkOSVulnerabilityDetails` instead of `*tools.Vulnerability`
- [ ] Update other vulnerability retrieval methods to use consistent return types
- [ ] Ensure repository layer properly populates CVE, CWE, and NetworkOS info from database queries
- [ ] Verify OWASP categories come from database `cwe_details.owasp_top10_category` field

### AC3: Update Vulnerability Handlers
- [ ] Modify `VulnerabilityHandlers.GetVulnerability` to work with NetworkOSVulnerabilityDetails
- [ ] Update response mapping to use NetworkOSVulnerabilityDetails fields
- [ ] Ensure API responses include database-driven OWASP categories
- [ ] Maintain backward compatibility in API response structure

### AC4: Update Response DTOs
- [ ] Create or update DTOs to map from NetworkOSVulnerabilityDetails
- [ ] Ensure OWASP Top 10 categories are properly exposed in API responses
- [ ] Maintain existing API contract while using new domain model internally
- [ ] Add proper null handling for optional CVE/CWE data

### AC5: Comprehensive Testing
- [ ] Update all vulnerability service unit tests to use NetworkOSVulnerabilityDetails
- [ ] Update handler tests to verify correct NetworkOSVulnerabilityDetails integration
- [ ] Add integration tests to verify OWASP categories come from database
- [ ] Ensure existing API functionality remains unchanged (regression testing)
- [ ] Test edge cases: missing CVE data, missing CWE data, invalid OWASP categories

### AC6: Performance and Quality Assurance
- [ ] Verify no performance degradation in vulnerability API endpoints
- [ ] Ensure proper error handling when CVE/CWE data is missing
- [ ] Run full test suite and ensure all tests pass
- [ ] Execute `make audit` and resolve any static analysis issues

---

## Technical Details

### Files Requiring Updates

**Service Layer:**
- `/pkg/services/vulnerability.go`:
  - Lines 202-329: `GetScanVulnerabilityDetail` method needs complete refactor
  - Remove complex domain object construction (lines 222-326)
  - Use `parseNetworkOSVulnerabilityWithDetails` from repository
  - Leverage NetworkOSVulnerabilityDetails methods for derived fields

**Interface Definitions:**
- `/pkg/interfaces/vulnerability.go`:
  - Line 16: Update `GetScanVulnerabilityDetail` return type
  - Line 42: Update `GetVulnerabilityByID` return type
  - Ensure consistency across all vulnerability-related interface methods

**Handler Layer:**
- `/pkg/handlers/vulnerability.go`:
  - Lines 29-93: `GetVulnerability` method needs updates
  - Line 37: Update service call to work with NetworkOSVulnerabilityDetails
  - Lines 53-92: Update response mapping to use new domain model fields

**Repository Layer:**
- `/pkg/storage/vulnerability.go`:
  - Update methods to return NetworkOSVulnerabilityDetails consistently
  - Ensure proper use of `parseNetworkOSVulnerabilityWithDetails` 
  - Remove legacy `IntermediateDetailData` usage if still present

### Key Integration Points

**Domain Model Usage:**
```go
// Current approach in service layer
vulnDetail := domain.ScanVulnerabilityDetail{
    // Manual field mapping...
}

// Target approach using NetworkOSVulnerabilityDetails
networkOSVuln := parseNetworkOSVulnerabilityWithDetails(dbResult)
owaspCategory := networkOSVuln.GetOwaspCategory()
primaryMetric := networkOSVuln.GetPrimaryCVSSMetric()
```

**OWASP Category Integration:**
- Ensure `NetworkOSVulnerabilityDetails.CWE.OwaspTop10Category` is populated from `cwe_details.owasp_top10_category`
- Use `GetOwaspCategory()` method instead of runtime mapping
- Handle cases where CWE data may be missing

**Response Transformation:**
```go
// Use NetworkOSVulnerabilityDetails methods for consistent API responses
response := dto.ScanVulnerabilityDetailResponse{
    Type: networkOSVuln.GetOwaspCategory().String(),
    MaxCVSS: networkOSVuln.GetPrimaryCVSSMetric().BaseScore,
    // ... other fields from new domain model
}
```

### Testing Strategy

**Unit Tests:**
- Mock NetworkOSVulnerabilityDetails in service tests
- Verify OWASP categories come from domain model, not runtime mapping
- Test edge cases with missing CVE/CWE data

**Integration Tests:**
- End-to-end API tests using real database data
- Verify OWASP categories match database values
- Ensure API responses maintain backward compatibility

**Regression Testing:**
- Compare API responses before/after changes
- Verify no functional changes in vulnerability retrieval
- Confirm performance metrics remain stable

---

## Definition of Done

- [ ] All vulnerability API endpoints use NetworkOSVulnerabilityDetails internally
- [ ] OWASP Top 10 categories are sourced from database via CWE records
- [ ] No runtime OWASP mapping logic remains in vulnerability flows
- [ ] All unit tests pass with new domain model
- [ ] Integration tests verify database-driven OWASP categories
- [ ] API responses maintain backward compatibility
- [ ] Code review completed and approved
- [ ] `make audit` passes without errors
- [ ] Documentation updated if API contracts changed

---

## Risk Assessment

**Low Risk:**
- Domain model is well-tested and stable
- Storage layer already supports new model
- Changes are mostly internal refactoring

**Potential Issues:**
- API response format changes could break clients
- Missing null handling for CVE/CWE data
- Performance impact from additional database joins

**Mitigation:**
- Maintain strict API backward compatibility
- Add comprehensive null checking
- Monitor performance during testing phase
- Rollback plan: Revert to previous service implementations

---

## Dependencies

- ✅ NetworkOSVulnerabilityDetails domain model (completed)
- ✅ Database schema with OWASP categories (completed)
- ✅ Storage layer parsing functions (completed)
- No external team dependencies
- No infrastructure changes required

---

## Estimated Timeline

**Day 1:** Service layer refactoring and interface updates
**Day 2:** Handler updates and DTO modifications  
**Day 3:** Comprehensive testing and bug fixes
**Day 4:** Code review, quality assurance, and documentation

**Total Estimate:** 4 development days