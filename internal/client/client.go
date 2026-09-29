package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	BaseURL string
	Token   string
	http    *http.Client
}

func New(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

type APIError struct {
	Status int 
	Message string 
}

func(e *APIError) Error() string {
	return fmt.Sprintf("server returned %d: %s" , e.Status , e.Message)
}

//do sends one req body is sent as json , receives the decoded json resp
func (c *Client) do(method , path string , body any , out any) error {
	var reqBody io.Reader
	if body != nil {
		data , err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w" , err) 
		}
		reqBody = bytes.NewReader(data)
	}
	req , err := http.NewRequest(method , c.BaseURL+path , reqBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp , err := c.http.Do(req) 
	if err != nil {
		return fmt.Errorf("request failed: %w" , err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return &APIError{Status: resp.StatusCode , Message: e.Error}
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}