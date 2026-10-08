package client

import (
	"encoding/base64"
	"fmt"
	"net/url"
)

func (c *Client) Register(email string, salt, authHash, wrappedVK, recoveryWrapped, recoveryAuth []byte) error {
	enc := base64.StdEncoding.EncodeToString
	body := struct {
		Email              string `json:"email"`
		Salt               string `json:"salt"`
		AuthHash           string `json:"auth_hash"`
		WrappedVaultKey    string `json:"wrapped_vault_key"`
		RecoveryWrappedKey string `json:"recovery_wrapped_key"`
		RecoveryAuthHash   string `json:"recovery_auth_hash"`
	}{
		Email:              email,
		Salt:               enc(salt),
		AuthHash:           enc(authHash),
		WrappedVaultKey:    enc(wrappedVK),
		RecoveryWrappedKey: enc(recoveryWrapped),
		RecoveryAuthHash:   enc(recoveryAuth),
	}
	return c.do("POST", "/register", body, nil)
}

func (c *Client) GetSalt(email string) ([]byte, error) {
	var resp struct {
		Salt string `json:"salt"`
	}
	if err := c.do("GET", "/salt?email="+url.QueryEscape(email), nil, &resp); err != nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(resp.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	return salt, nil
}

func (c *Client) Login(email string, authHash []byte) (string, []byte, error) {
	body := struct {
		Email    string `json:"email"`
		AuthHash string `json:"auth_hash"`
	}{
		Email:    email,
		AuthHash: base64.StdEncoding.EncodeToString(authHash),
	}
	var resp struct {
		Token           string `json:"token"`
		WrappedVaultKey string `json:"wrapped_vault_key"`
	}
	if err := c.do("POST", "/login", body, &resp); err != nil {
		return "", nil, err
	}
	wrappedVK, err := base64.StdEncoding.DecodeString(resp.WrappedVaultKey)
	if err != nil {
		return "", nil, fmt.Errorf("decode wrapped vault key: %w", err)
	}
	return resp.Token, wrappedVK, nil
}

func (c *Client) ChangePassword(oldAuth, newSalt, newAuth, newWrappedVK []byte) error {
	enc := base64.StdEncoding.EncodeToString
	body := struct {
		OldAuthHash        string `json:"old_auth_hash"`
		NewSalt            string `json:"new_salt"`
		NewAuthHash        string `json:"new_auth_hash"`
		NewWrappedVaultKey string `json:"new_wrapped_vault_key"`
	}{
		OldAuthHash:        enc(oldAuth),
		NewSalt:            enc(newSalt),
		NewAuthHash:        enc(newAuth),
		NewWrappedVaultKey: enc(newWrappedVK),
	}
	return c.do("PUT", "/me/password", body, nil)
}

func (c *Client) RecoverKey(email string, recAuth []byte) ([]byte, error) {
	body := struct {
		Email            string `json:"email"`
		RecoveryAuthHash string `json:"recovery_auth_hash"`
	}{
		Email:            email,
		RecoveryAuthHash: base64.StdEncoding.EncodeToString(recAuth),
	}
	var resp struct {
		RecoveryWrappedKey string `json:"recovery_wrapped_key"`
	}
	if err := c.do("POST", "/recover/key", body, &resp); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp.RecoveryWrappedKey)
}

func (c *Client) RecoverReset(email string, recAuth, newSalt, newAuth, newWrappedVK []byte) error {
	enc := base64.StdEncoding.EncodeToString
	body := struct {
		Email              string `json:"email"`
		RecoveryAuthHash   string `json:"recovery_auth_hash"`
		NewSalt            string `json:"new_salt"`
		NewAuthHash        string `json:"new_auth_hash"`
		NewWrappedVaultKey string `json:"new_wrapped_vault_key"`
	}{
		Email:              email,
		RecoveryAuthHash:   enc(recAuth),
		NewSalt:            enc(newSalt),
		NewAuthHash:        enc(newAuth),
		NewWrappedVaultKey: enc(newWrappedVK),
	}
	return c.do("POST", "/recover/reset", body, nil)
}