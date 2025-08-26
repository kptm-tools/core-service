# Stage 1: Builder - for compiling dependencies
FROM golang:1.24.6 AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY cmd/ ./cmd
COPY /pkg ./pkg
COPY db/ ./db
COPY docs/ ./docs
COPY data/ ./data

# Install the 'air' live-reloading tool
RUN go install github.com/air-verse/air@latest

# Stage 2: Development - for running the application with live reload
FROM golang:1.24.6 AS development

WORKDIR /app

COPY --from=builder /go/pkg/mod /go/pkg/mod
COPY --from=builder /go/bin/air /go/bin/air

COPY .air.toml .
COPY Makefile .

COPY . .

EXPOSE 8000

# The command to run the application using air for live-reloading
CMD ["air"]

# Stage 3: Production builder - for building the production binary
FROM golang:1.24.6 AS production-builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY cmd/ ./cmd
COPY /pkg ./pkg
COPY db/ ./db
COPY docs/ ./docs
COPY data/ ./data

# Build main application
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o ./bin/core-service ./cmd/main.go

# Build migration tool
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o ./bin/db_tool ./db/db_tool/main.go

# Stage 4: Production - minimal final image
FROM alpine:3.19 AS production

RUN apk --no-cache add ca-certificates curl

WORKDIR /app

# Copy binaries
COPY --from=production-builder /app/bin/core-service /app/core-service
COPY --from=production-builder /app/bin/db_tool /app/db_tool

# Copy necessary data and configuration files
COPY --from=production-builder /app/db /app/db
COPY --from=production-builder /app/data /app/data
COPY --from=production-builder /app/docs /app/docs

# Make binaries executable
RUN chmod +x /app/core-service /app/db_tool

EXPOSE 8000

# Note: We don't use USER nobody here because db_tool needs to run as root
# The application itself should handle dropping privileges if needed

CMD ["/app/core-service"]
