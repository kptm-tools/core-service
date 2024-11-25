package main

import (
	"log"

	"github.com/kptm-tools/core-service/pkg/http"
)

func main() {

	s := http.NewAPIServer(":8000")

	err := s.Init()

	if err != nil {
		log.Fatalf("Error initializing APIServer: `%v`", err)
	}

}
