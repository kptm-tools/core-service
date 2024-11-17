.PHONY: fmt vet build

fmt:
	go fmt ./...

vet:	fmt
	go vet ./...

build: vet
	go build -o ./bin/core-service 

run: build
	./bin/core-service

test:
	go test -v ./...
