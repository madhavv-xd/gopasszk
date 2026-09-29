package main

import "os"

func serverURL() string {
	if u := os.Getenv("GOPASS_SERVER"); u != "" {
		return u
	}
	return "http://localhost:8080"
}