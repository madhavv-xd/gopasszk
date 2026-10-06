package main

import (
	"os"
	"net/url"
	"errors"
)

func serverURL() (string , error){
	raw := os.Getenv("GOPASS_SERVER")
	if raw == "" {
		raw = "http://localhost:8080"
	}
	parsed , err := url.Parse(raw)
	if err != nil {
		return "" , err 
	}
	if parsed.Scheme == "https" {
    return raw, nil
	}
	if parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1")  {
		return raw , nil
	}
	return  "" , errors.New("GOPASS_SERVER must use https")
}