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
| `make run`           | Run the application locally.                 |
| `make run/live`      | Run the application with live reload.        |
| `make populate`      | Populate the database with sample data.      |
| `make clear`         | Clear all database tables (requires confirm).|

#### Quality Control
| Command              | Description                                   |
|----------------------|-----------------------------------------------|
| `make audit`         | Run static analysis and vulnerability checks.|
| `make test`          | Run all tests.                               |
| `make test/cover`    | Run tests with coverage report.              |

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
