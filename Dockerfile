FROM golang:1.23.2

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY *.go ./

COPY /docs ./docs

RUN CGO_ENABLED=0 GOOS=linux go build -o ./bin/core-service 

EXPOSE 8000

CMD ["./bin/core-service"]
