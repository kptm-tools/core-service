# Core-Service 🚀

Welcome to **Core-Service**, the heart of the Kriptome-Tools project! This service manages the core domain logic, including database connections, tenants, users, scans, and more. Below, you'll find everything you need to get started with running, testing, and deploying Core-Service. 💼🔐

---

## 🛠️ Features

- **Tenant Management**: Handle multiple tenants with ease.
- **User Management**: Define and manage users within the system.
- **Scan Orchestration**: Automate and manage scans with robust workflows.
- **Database Integration**: Seamless PostgreSQL integration for reliable data persistence.
- **Authentication Support**: Integrated with FusionAuth for secure identity management.

---

## 🚀 Quick Start

### Prerequisites
1. **Install Docker & Docker Compose**.
2. **Environment Variables**:
   - Configure the required environment variables in a `.env` file.
   - An example can be found in `.env.example` in the root directory
   * You may set variables within the `Makefile` such as `DATABASE_URL` too.

### Steps
1. Clone this repository:
   ```bash
   git clone https://github.com/your-org/core-service.git
   cd core-service
   ```
2. Build and run the service:
   ```bash
   docker-compose up --build
   ```
3. Access the service:
   - API: [http://localhost:8000](http://localhost:8000)
   - Healthcheck: [http://localhost:8000/healthcheck](http://localhost:8000/healthcheck)

---

## 🛠️ Development

### Commands

#### Makefile Helpers
| Command              | Description                                   |
|----------------------|-----------------------------------------------|
| `make help`          | Display all available commands.              |
| `make tidy`          | Tidy mod files and format Go files.          |
| `make build`         | Build the application binary.                |
| `make swagger`       | Build the swagger file with current code.    |
| `make run`           | Run the application locally.                 |
| `make run/live`      | Run the application with live reload.        |
| `make populate`      | Populate the database with sample data.      |
| `make populate-cwe`  | Populate CWE details and mitigations from data/cwe.json. |
| `make clear`         | Clear all database tables (requires confirm).|
| `make migrate/create NAME=<name>`        | Create a new migration file. |
| `make migrate/up`        | Apply all up migrations. |
| `make migrate/down`        | Apply the latest down migration. |




#### Quality Control
| Command              | Description                                   |
|----------------------|-----------------------------------------------|
| `make audit`         | Run static analysis and vulnerability checks.|
| `make test`          | Run all tests.                               |
| `make test/cover`    | Run tests with coverage report.              |

---

## 🔒 CWE Data Management

Core-Service includes a command-line tool for populating the database with comprehensive CWE (Common Weakness Enumeration) data. This creates a pre-populated knowledge base of security weaknesses and their mitigations, optimizing the vulnerability ingestion pipeline.

### CWE Data Population

**Prerequisites:**
- Ensure database migrations are up to date: `make migrate/up`
- The `data/cwe.json` file must be present (copied from vulnerability-analysis service)

**Command:**
```bash
make populate-cwe
```

This command:
- Creates special CWE records for edge cases (`CWE-Other` and `CWE-noinfo`)
- Reads and parses the CWE JSON data from `data/cwe.json`
- Populates the `cwe_details` table with weakness information
- Populates the `cwe_mitigations` table with remediation strategies
- Uses upsert logic (safe to run multiple times)
- Provides progress updates during execution

**Manual execution:**
```bash
go run ./db/db_tool/main.go populate-cwe
```

### CWE Data Validation

To validate the CWE JSON parsing without database operations:

```bash
go run ./cmd/test-cwe/main.go
```

This test utility:
- Validates that `data/cwe.json` is properly formatted
- Shows parsing statistics and sample data
- Helps debug CWE data issues during development
- Can be run independently of database setup

### Updating CWE Data

When the CWE JSON file is updated:
1. Replace `data/cwe.json` with the new file
2. Optionally validate: `go run ./cmd/test-cwe/main.go`
3. Repopulate the database: `make populate-cwe`

The population process is idempotent and will update existing records while preserving referential integrity.

---

## 🐳 Docker Usage

### Build and Run
```bash
docker-compose up --build
```

### Core Service Configuration
- Exposed on: `http://localhost:8000`
- Dependencies:
  - PostgreSQL database
  - FusionAuth for authentication
  - OpenSearch for logging and search

---

## 📂 Project Structure

| Directory | Purpose                                      |
|-----------|----------------------------------------------|
| `/cmd`    | Main application entry points and utilities.|
| `/pkg`    | Core libraries and reusable components.     |
| `/docs`   | Documentation and swagger file.             |
| `/db`     | Database layer with SQL and SQLc with Tools.|
| `/bin`    | Compiled binary artifacts.                  |

---

## 🧪 Testing

Run all tests with:
```bash
make test
```

For a coverage report:
```bash
make test/cover
```

---

**Happy Coding!** 🎉
