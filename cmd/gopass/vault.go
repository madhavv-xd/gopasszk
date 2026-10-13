package main

import (
	"github.com/madhavv-xd/gopasszk/internal/client"
	"github.com/madhavv-xd/gopasszk/internal/vault"
)

// unlock asks for the master password, checks it by logging in,
// and returns a ready client plus the encryption key.
func unlock() (*client.Client, []byte, error) {
	s, err := loadSession()
	if err != nil {
		return nil, nil, err
	}
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return nil, nil, err
	}

	u, err := serverURL()
	if err != nil {
		return nil, nil, err
	}
	return vault.Unlock(u, s.Email, []byte(pw))
}
