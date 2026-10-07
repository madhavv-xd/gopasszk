package client

import (
	"net/url"
	"time"
)

type Credential struct {
	ID                 string    `json:"id"`
	SiteName           string    `json:"site_name"`
	UsernameCiphertext string    `json:"username_ciphertext"`
	PasswordCiphertext string    `json:"password_ciphertext"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type credentialBody struct {
	SiteName           string `json:"site_name"`
	UsernameCiphertext string `json:"username_ciphertext"`
	PasswordCiphertext string `json:"password_ciphertext"`
}

func (c *Client) CreateCredential(site, userCT, passCT string) (Credential, error) {
	var out Credential
	err := c.do("POST", "/credentials", credentialBody{site, userCT, passCT}, &out)
	return out, err
}

func (c *Client) ListCredentials() ([]Credential, error) {
	var resp struct {
		Credentials []Credential `json:"credentials"`
	}
	err := c.do("GET", "/credentials", nil, &resp)
	return resp.Credentials, err
}

func (c *Client) SearchCredentials(q string) ([]Credential, error) {
	params := url.Values{}
	params.Set("q", q)

	var resp struct {
		Credentials []Credential `json:"credentials"`
	}
	err := c.do("GET", "/credentials?"+params.Encode(), nil, &resp)
	return resp.Credentials, err
}

func (c *Client) UpdateCredential(id, site, userCT, passCT string) error {
	return c.do("PUT", "/credentials/"+id, credentialBody{site, userCT, passCT}, nil)
}

func (c *Client) DeleteCredential(id string) error {
	return c.do("DELETE", "/credentials/"+id, nil, nil)
}