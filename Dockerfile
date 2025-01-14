FROM golang:1.23.2

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY cmd/ ./cmd

COPY /pkg ./pkg

RUN CGO_ENABLED=0 GOOS=linux go build -o ./bin/core-service ./cmd/core-server/main.go

EXPOSE 8000

CMD ["./bin/core-service"]
