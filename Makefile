# Change these variables as necessary
main_package_path = ./cmd
sample_package_path = ./cmd/sample_data.go
binary_name = core-service
DATABASE_URL = 

# ==================================================================================== #
# HELPERS
# ==================================================================================== #

## help: print this help message
.PHONY: help
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

.PHONY: confirm
confirm:
	@echo -n 'Are you sure? [y/N] ' && read ans && [ $${ans:-N} = y ]

# ==================================================================================== #
# DEVELOPMENT
# ==================================================================================== #

## tidy: tidy modfiles and format .go files
.PHONY: tidy
tidy:
	go mod tidy -v
	go fmt ./...

## build: build the application
.PHONY: build
build: tidy
	go build -o=./bin/${binary_name} ${main_package_path}

## run: run the application
.PHONY: run
run: build
	./bin/${binary_name}

## run/live: run the application with reloading on file changes
.PHONY: run/live
run/live:
	go run github.com/cosmtrek/air@v1.43.0 \
		--build.cmd "make build" --build.bin "./bin/${binary_name}" --build.delay "100" \
		--build.exclude_dir "" \
		--build.include_ext "go, tpl, tmpl, html, css, scss, js, ts, sql, jpeg, jpg, git, png, bmp, wbp, ico" \
		--misc.clean_on_exit "true"

# ==================================================================================== #
# DATABASE MIGRATIONS
# ==================================================================================== #

## migrate/create NAME=<name>: create a new migration file
.PHONY: migrate/create
migrate/create:
	@if [ -z "$(NAME)" ]; then \
		echo "Usage: make migrate/create NAME=<migration-name>"; \
		exit 1; \
	fi
	migrate create -ext sql -dir cmd/migrations -seq $(NAME)

## migrate/up: apply all up migrations
.PHONY: migrate/up
migrate/up:
	migrate -database $(DATABASE_URL) -path cmd/migrations up

## migrate/down: apply the latest down migration
.PHONY: migrate/down
migrate/down:
	migrate -database $(DATABASE_URL) -path cmd/migrations down

## migrate/force VERSION=<version>: force a specific miration version
.PHONY: migrate/force
migrate/force:
	@if [ -z "$(VERSION)" ]; then \
		echo "Usage: make migrate/force VERSION=<version>"; \
		exit 1; \
	fi
	migrate -database $(DATABASE_URL) -path cmd/migrations force $(VERSION)

## populate: populate DB with sample data
.PHONY: populate
populate:
	go run ${sample_package_path} populate

## clear: clear DB tables
.PHONY: clear
clear: confirm
	go run ${sample_package_path} clear


# ==================================================================================== #
# QUALITY CONTROL
# ==================================================================================== #

## audit: run quality control checks (static, vulnerabilities, etc)
.PHONY: audit
audit: test
	go mod tidy -diff
	go mod verify
	test -z "$(shell gofmt -l .)" 
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@latest -checks=all,-ST1000,-U1000 ./...
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

## test: run all tests
.PHONY: test
test:
	go test -v -race -buildvcs ./...

## test/cover: run all tests and display coverage
.PHONY: test/cover
test/cover:
	go test -v -race -buildvcs -coverprofile=/tmp/coverage.out ./...
	go tool cover -html=/tmp/coverage.out


