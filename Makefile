# Change these variables as necessary
main_package_path = ./cmd
sample_package_path = ./db/sampledata/main.go
binary_name = core-service
migrations_main = ./db/db_tool/main.go

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

## swagger: run the swagger generator
.PHONY: swagger
swagger:
	swag init \
		--parseDependency \
		--parseDepth 1 \
		-g pkg/api/api.go \
		-d .

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
	go run ${migrations_main} create $(NAME)

## migrate/up: apply all up migrations
.PHONY: migrate/up
migrate/up:
	go run ${migrations_main} up

## migrate/down: apply the latest down migration
.PHONY: migrate/down
migrate/down:
	go run ${migrations_main} down

## migrate/rollback: rollback one step
.PHONY: migrate/rollback
migrate/rollback:
	go run ${migrations_main} rollback

## migrate/drop: drop all migration tables
.PHONY: migrate/drop
migrate/drop:
	go run ${migrations_main} drop

## migrate/force VERSION=<version>: force a specific migration version
.PHONY: migrate/force
migrate/force:
	@if [ -z "$(VERSION)" ]; then \
		echo "Usage: make migrate/force VERSION=<version>"; \
		exit 1; \
	fi
	go run ${migrations_main} force $(VERSION)

## generate: generate sqlc code
.PHONY: generate
generate:
	go run ${migrations_main} gen

## populate: populate DB with sample data
.PHONY: populate
populate:
	go run ${sample_package_path} populate

## populate-cwe: populate DB with CWE data from data/cwe.json
.PHONY: populate-cwe
populate-cwe:
	go run ${migrations_main} populate-cwe

## clear: clear DB tables
.PHONY: clear
clear: confirm
	go run ${sample_package_path} clear


# ==================================================================================== #
# QUALITY CONTROL
# ==================================================================================== #

## audit: run quality control checks (static, vulnerabilities, etc)
.PHONY: audit
audit: test test/cwe
	go mod tidy -diff
	go mod verify
	test -z "$(shell gofmt -l .)" 
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@master -checks=all,-ST1000,-U1000 ./...
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

## test: run all tests
.PHONY: test
test:
	go test -v -race -buildvcs ./...


## test/cwe: validate CWE JSON parsing
.PHONY: test/cwe
test/cwe:
	go run ./cmd/test-cwe/main.go

## test/cover: run all tests and display coverage
.PHONY: test/cover
test/cover:
	go test -v -race -buildvcs -coverprofile=/tmp/coverage.out ./...
	go tool cover -html=/tmp/coverage.out

## test/bench: run all benchmark tests
.PHONY: test/bench
test/bench:
	go test -bench=. -benchmem ./...
