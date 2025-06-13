FROM golang:1.24.4

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY cmd/ ./cmd

COPY /pkg ./pkg

RUN CGO_ENABLED=0 GOOS=linux go build -o ./bin/core-service ./cmd/main.go

EXPOSE 8000

CMD ["./bin/core-service"]
