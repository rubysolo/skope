// Package client calls a skope server's admin API.
package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rubysolo/skope/internal/api"
)

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// FromEnv builds a client from SKOPE_URL and SKOPE_ADMIN_TOKEN.
func FromEnv() (*Client, error) {
	base, token := os.Getenv("SKOPE_URL"), os.Getenv("SKOPE_ADMIN_TOKEN")
	if base == "" || token == "" {
		return nil, errors.New("set SKOPE_URL and SKOPE_ADMIN_TOKEN to manage a skope server")
	}
	return &Client{BaseURL: strings.TrimSuffix(base, "/"), Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}, nil
}

func (c *Client) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e api.Error
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s (%d)", e.Error, resp.StatusCode)
		}
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *Client) Projects() ([]api.Project, error) {
	var out []api.Project
	return out, c.do("GET", "/v1/projects", nil, &out)
}

func (c *Client) CreateProject(name string) (api.ProjectToken, error) {
	var out api.ProjectToken
	return out, c.do("POST", "/v1/projects", api.CreateProject{Name: name}, &out)
}

func (c *Client) RotateToken(name string) (api.ProjectToken, error) {
	var out api.ProjectToken
	return out, c.do("POST", "/v1/projects/"+url.PathEscape(name)+"/token", nil, &out)
}

func (c *Client) ArchiveProject(name string) error {
	return c.do("POST", "/v1/projects/"+url.PathEscape(name)+"/archive", nil, nil)
}

func (c *Client) DeleteProject(name string) error {
	return c.do("DELETE", "/v1/projects/"+url.PathEscape(name), nil, nil)
}

func (c *Client) Findings(project string, includeResolved bool) ([]api.Finding, error) {
	q := url.Values{}
	if project != "" {
		q.Set("project", project)
	}
	if includeResolved {
		q.Set("all", "1")
	}
	var out []api.Finding
	return out, c.do("GET", "/v1/findings?"+q.Encode(), nil, &out)
}

func (c *Client) Ignore(id int64, reason, until string) error {
	return c.do("PUT", fmt.Sprintf("/v1/findings/%d/ignore", id), api.Ignore{Reason: reason, Until: until}, nil)
}

func (c *Client) Unignore(id int64) error {
	return c.do("DELETE", fmt.Sprintf("/v1/findings/%d/ignore", id), nil, nil)
}

func (c *Client) Sync() error { return c.do("POST", "/v1/sync", nil, nil) }
