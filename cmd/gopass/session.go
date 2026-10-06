package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type session struct {
	Email string `json:"email"`
	Token string `json:"token"`
}

func sessionPath() (string, error) {
	dir, err := os.UserConfigDir() // on Windows: %AppData%
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "gopass", "session.json"), nil
}

func saveSession(s session) error {
	path, err := sessionPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func deleteSession() error {
	path , err := sessionPath()
	if err != nil {
		return err 
	}
	err = os.Remove(path)
	if errors.Is(err , os.ErrNotExist){
		return errors.New("not logged in")
	}
	return err 
}

func loadSession() (session, error) {
	var s session
	path, err := sessionPath()
	if err != nil {
		return s, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, errors.New("not logged in: run 'gopass login' first")
	}
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(data, &s)
	return s, err
}