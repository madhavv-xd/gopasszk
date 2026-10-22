package main

import (
	"errors"
	"net/url"
	"os"
)

// defaultServer is overridden in release builds with
// -ldflags "-X main.defaultServer=https://...".
var defaultServer = "http://localhost:8080"

func serverURL() (string, error) {
	raw := os.Getenv("GOPASS_SERVER")
	if raw == "" {
		raw = defaultServer
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "https" {
		return raw, nil
	}
	if parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1") {
		return raw, nil
	}
	return "", errors.New("GOPASS_SERVER must use https")
}
