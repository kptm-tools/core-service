# Stage 1: Builder - for compiling dependencies
FROM golang:1.24.4 AS builder

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
FROM golang:1.24.4 AS development

WORKDIR /app

COPY --from=builder /go/pkg/mod /go/pkg/mod
COPY --from=builder /go/bin/air /go/bin/air

COPY .air.toml .
COPY Makefile .

COPY . .

EXPOSE 8000

# The command to run the application using air for live-reloading
CMD ["air"]

# Stage 3: Production - for building the production binary
FROM golang:1.24.4 AS production

WORKDIR /app

COPY go.mod go.sum ./
COPY Makefile ./

RUN go mod download

COPY cmd/ ./cmd
COPY /pkg ./pkg
COPY db/ ./db
COPY docs/ ./docs
COPY data/ ./data

RUN CGO_ENABLED=0 GOOS=linux go build -o ./bin/core-service ./cmd/main.go

EXPOSE 8000

CMD ["./bin/core-service"]
