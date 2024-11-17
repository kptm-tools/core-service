package main

import "log"

func main() {

	s := NewAPIServer(":8000")

	err := s.Init()

	if err != nil {
		log.Fatalf("Error initializing APIServer: `%v`", err)
	}

}
