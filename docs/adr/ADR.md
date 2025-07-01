# ADR-001: DTO Struct Patterns for Representing Optional Fields in API Responses

**Status:** Accepted  
**Date:** 2025-07-01  

## 💭 Context

When designing API response DTOs (data transfer objects) in Go, representing optional fields accurately is important. Our backend handles vulnerability data that includes fields which might be explicitly `null` or simply absent in JSON responses, reflecting the underlying database values or API semantics.

To provide a clean and predictable API contract, we needed a consistent pattern for modeling optional fields so that:

- Consumers can clearly distinguish between “field not set” and “field set as null”.
- JSON marshaling/unmarshaling behaves as expected.
- Struct definitions remain maintainable and idiomatic.

Two common patterns are available in Go:

- **Pointers for null values**: Using pointers (e.g., `*string`, `*int`) to represent nullable fields, where `nil` means the value is explicitly null.
- **`omitempty` tag**: Using the `omitempty` struct tag to omit fields that have zero values from the JSON output, modeling implicit absence.

## ⚖️ Alternatives Considered

### Alternative 1: Use pointers for all optional fields without `omitempty`

- Pros:
  - Explicitly represents presence or absence (`nil` vs set value).
  - JSON will include fields with `null` value if pointer is nil (if no `omitempty` used).
- Cons:
  - All optional fields appear in JSON even if null, which might clutter responses.
  - Consumers must handle explicit nulls.

### Alternative 2: Use value types with `omitempty` only

- Pros:
  - Keeps JSON payloads smaller by omitting empty values.
  - Simpler struct definitions for some fields.
- Cons:
  - Cannot distinguish between "zero value" and "absent value".
  - Less explicit about null semantics.

### Alternative 3: Combine pointers and `omitempty` where appropriate (Chosen approach)

- Use pointers (`*Type`) for fields where explicit null values are semantically significant.
- Use `omitempty` tag on pointer fields to exclude absent/null values from JSON output.
- Use value types with `omitempty` for truly optional fields with no need to distinguish explicit null.

- Pros:
  - Flexible and explicit optionality representation.
  - Keeps JSON payloads concise while maintaining clarity.
  - Matches expectations for APIs consuming this data.
- Cons:
  - Slightly more complex structs and marshaling logic.
  - Developers must understand pointer semantics and JSON tags properly.

## 💪 Decision

We decided to adopt **Alternative 3**—a combined approach using pointers for fields that require explicit nullability, paired with the `omitempty` JSON struct tag to omit absent fields during marshaling.

Implementation details:

- Fields representing optional/nilable values are pointers annotated with `omitempty`:

  ```go
  type VulnerabilityDTO struct {
      CWEID   *int    `json:"cwe_id,omitempty"`   // nil means explicitly null or absent
      Summary string  `json:"summary"`            // always present
      Details *string `json:"details,omitempty"`  // optional descriptive details
  }
  ```

- This approach gives precise control over the API’s JSON output, aligning with frontend expectations and database NULL semantics.
- Where fields are required or always present, plain value types without `omitempty` are used.

## ➡️ Consequences

### ✅ Positive

- Clear and predictable handling of optional and null fields in API responses.
- Consumers of the API can distinguish between "value missing" and "value explicitly null".
- JSON payloads are concise, omitting unnecessary or empty fields while preserving semantic clarity.
- Provides a consistent pattern for DTO definition useful across the codebase.

### ❌ Negative

- Developers must understand pointer usage and JSON marshaling nuances in Go.
- Slightly increased complexity in DTO code and JSON handling.
- Some fields now use pointers, which may require additional nil checks in consuming code.

---

This ADR serves as a reference for the team when designing future API data transfer objects requiring nuanced representation of optional or nullable data.

---
