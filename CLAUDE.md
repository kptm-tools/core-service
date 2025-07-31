# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Essential Commands

### Development
```bash
# Build and run
make build                 # Build the binary
make run                   # Build and run
make run/live              # Run with auto-reload (requires air)

# Code quality
make tidy                  # Tidy mod files and format Go files
make swagger               # Generate Swagger documentation

# Testing
make test                  # Run all tests
make test/cover            # Run tests with coverage report
make audit                 # Run complete quality control (test + static analysis + vulnerability scan)
```

### Database Operations
```bash
# Migrations
make migrate/create NAME=migration_name  # Create new migration
make migrate/up            # Apply all up migrations
make migrate/down          # Apply latest down migration
make migrate/rollback      # Rollback one step
make migrate/drop          # Drop all migration tables
make migrate/force VERSION=<version>  # Force specific migration version

# SQLc code generation
make generate              # Generate Go code from SQL queries

# Sample data
make populate              # Populate DB with sample data
make clear                 # Clear DB tables (requires confirmation)
```

## Architecture Overview

### Microservice Design
Core-Service is a **vulnerability scanning backend service** implementing Domain-Driven Design (DDD) patterns. It serves as the main business logic point for the Kriptome-Tools vulnerability scanning platform.

### Core Dependencies
- **PostgreSQL**: Primary data store with SQLc for type-safe queries
- **FusionAuth**: External authentication service
- **NATS**: Event bus for scan orchestration
- **SMTP**: Email notifications for scan results

### DDD Structure
```
pkg/
├── domain/           # Domain entities and business logic
├── interfaces/       # Port interfaces (service & repository contracts)
├── services/         # Application services (use cases)
├── handlers/         # HTTP handlers (adapters)
├── storage/          # Repository implementations
├── events/           # Event-driven architecture
│   └── consumers/    # NATS event consumers
└── ws/              # WebSocket hubs for real-time updates
    ├── scan/        # Scan progress updates
    └── report/      # Report generation
```

### Key Architectural Patterns

**Dependency Injection**
- Constructor-based DI in `cmd/main.go`
- All dependencies are interfaces, enabling easy mocking
- Services composed in main() with explicit wiring

**Repository Pattern**
- SQLc generates type-safe Go code from SQL queries
- Repositories implement interfaces defined in `pkg/interfaces/`
- Transaction support via `TxManager` interface

**Event-Driven Scanning**
- NATS subjects: DNSLookup, WhoIs, Harvester, Nmap, WebScan, ScanFailed
- Each tool publishes results to NATS
- Core-Service consumes events and updates scan state

**Domain Entities**
- `Scan`: Central aggregate for vulnerability scans
- `Host`: Target systems for scanning
- `Vulnerability`: Security findings (CVE/CWE/WASC)
- `ScanSchedule`: Cron-based scan scheduling

### Testing Patterns

**Mock-Based Unit Tests**
- Mocks in `pkg/mocks/` for all interfaces
- Constructor injection enables test isolation
- Example test pattern:
```go
mockRepo := &mock.MockScanRepo{
    MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
        return testScan, nil
    },
}
service := services.NewScanService(mockVulnRepo, mockRepo, mockHostRepo, mockResultRepo)
```

**Test Utilities**
- `pkg/testutil/context.go`: Test context helpers
- `pkg/samples/`: Domain object factories for tests

### Database Schema

**Key Tables**
- `tenants`: Multi-tenancy support
- `hosts`: Scan targets with credentials
- `scans`: Scan instances with status tracking
- `scan_results`: Tool-specific results storage
- `vulnerabilities`: CVE/CWE findings
- `services`: Discovered services/ports
- `operating_systems`: OS detection results

**Migrations**
- Located in `db/sql/migrations/`
- Use `make migrate/create NAME=description` for new migrations
- Triggers for scan status updates and notifications

### Event Flow

1. **Scan Initiation**: API request → Create scan → Publish to NATS
2. **Tool Execution**: External tools consume events, execute, publish results
3. **Result Processing**: Core-Service consumes results → Updates DB → WebSocket notifications
4. **Completion**: All tools finish → Calculate protection score → Send email report

### WebSocket Architecture

**Scan Hub** (`/ws/scan`):
- Real-time scan progress updates
- Broadcasts to all connected clients per tenant

**Report Hub** (`/ws/report/`):
- Interactive report generation
- Room-based collaboration for vulnerability vector selection

### Configuration

Required environment variables:
```bash
# Database
DB_USER, DB_PASSWORD, DB_NAME, DB_HOST, DB_PORT

# FusionAuth
FUSIONAUTH_API_KEY, FUSIONAUTH_HOST, FUSIONAUTH_PORT
APPLICATION_ID, FUSIONAUTH_BLUEPRINT_TENANTID, FUSIONAUTH_BLUEPRINT_APPID

# NATS
NATS_HOST, NATS_PORT, NATS_MONITOR_PORT

# SMTP
SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM_EMAIL

# Server
SERVER_HOST, SERVER_PORT, ALLOWED_ORIGINS
```

### Development Workflow

1. **Before implementing**: Review existing patterns in similar handlers/services
2. **Database changes**: Create migration, run `make generate` for SQLc
3. **New endpoints**: Add handler → service → repository layers with interfaces
4. **Testing**: Write unit tests with mocks for all new functionality
5. **Before committing**: Run `make audit` to ensure quality

### Common Patterns

**Service Creation**:
```go
func NewXService(repo interfaces.XRepository) interfaces.IXService {
    return &xService{repo: repo}
}
```

**Error Handling**:
- Services return domain-specific errors from `pkg/customerrors/`
- Handlers convert to HTTP responses
- Repository errors wrapped with context

**Context Usage**:
- All service methods accept `context.Context` as first parameter
- Extract tenant/user from context: `domain.GetTenantFromContext(ctx)`

**NATS Event Consumers**:
- Implement `HandleMessage(msg *nats.Msg)` 
- Unmarshal event data → Process → Update scan results
- Mark scan as failed on errors