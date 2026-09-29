package client

import (
	"encoding/base64"
	"fmt"
	"net/url"
)

func (c *Client) Register(email string, salt, authHash []byte) error {
	body := struct {
		Email    string `json:"email"`
		Salt     string `json:"salt"`
		AuthHash string `json:"auth_hash"`
	}{
		Email:    email,
		Salt:     base64.StdEncoding.EncodeToString(salt),
		AuthHash: base64.StdEncoding.EncodeToString(authHash),
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

func (c *Client) Login(email string, authHash []byte) (string, error) {
	body := struct {
		Email    string `json:"email"`
		AuthHash string `json:"auth_hash"`
	}{
		Email:    email,
		AuthHash: base64.StdEncoding.EncodeToString(authHash),
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := c.do("POST", "/login", body, &resp); err != nil {
		return "", err
	}
	return resp.Token, nil
}