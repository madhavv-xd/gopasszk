package main

import (
	"encoding/base64"
	"errors"

	"github.com/madhavv-xd/gopasszk/internal/client"
	"github.com/madhavv-xd/gopasszk/internal/crypto"
)

const nonceSize = 12

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

	u , err := serverURL()
	if err != nil {
		return nil , nil , err
	}
	c := client.New(u)
	salt, err := c.GetSalt(s.Email)
	if err != nil {
		return nil, nil, err
	}

	token, err := c.Login(s.Email, crypto.DeriveAuthHash(pw, salt))
	if err != nil {
		return nil, nil, errors.New("wrong master password")
	}
	c.Token = token

	key := crypto.DeriveEncryptionKey(pw, salt)
	return c, key, nil
}

func encryptField(key []byte, plaintext string) (string, error) {
	nonce, ct, err := crypto.Encrypt(key, []byte(plaintext))
	if err != nil {
		return "", err
	}
	combined := make([]byte, 0, len(nonce)+len(ct))
	combined = append(combined, nonce...)
	combined = append(combined, ct...)
	return base64.StdEncoding.EncodeToString(combined), nil
}

func decryptField(key []byte, encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	pt, err := crypto.Decrypt(key, data[:nonceSize], data[nonceSize:])
	if err != nil {
		return "", errors.New("decryption failed")
	}
	return string(pt), nil
}