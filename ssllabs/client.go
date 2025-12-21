package ssllabs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"paulrojasg/sslchecker/domain"
)

const defaultBaseURL = "https://api.ssllabs.com/api/v2/"

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func NewClient() *Client {
	return &Client{
		baseURL:    defaultBaseURL,
		httpClient: http.DefaultClient,
	}
}

func (c *Client) Analyze(ctx context.Context, host string, startNew bool) (*domain.HostReport, error) {
	req, err := http.NewRequestWithContext(ctx,
		"GET",
		c.baseURL+"/analyze",
		nil,
	)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add("host", host)
	if startNew {
		q.Add("startNew", "on")
	}
	req.URL.RawQuery = q.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var report domain.HostReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return nil, err
	}

	return &report, nil
}
