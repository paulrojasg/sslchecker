package ssllabs

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"paulrojasg/sslchecker/domain"
	"strconv"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func NewClient(baseUrl string) *Client {
	return &Client{
		baseURL:    baseUrl,
		httpClient: http.DefaultClient,
	}
}

func (c *Client) Analyze(ctx context.Context, host string, parameters domain.ScanParameters) (*domain.HostReport, error) {
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

	// Adding query parameters

	if parameters.New {
		q.Add("startNew", "on")
	}
	if parameters.Cache {
		q.Add("fromCache", "on")
		if parameters.MaxAge > 0 {
			q.Add("maxAge", strconv.FormatUint(uint64(parameters.MaxAge), 10))
		}
	}
	if parameters.All != "" {
		q.Add("all", parameters.All)
	}
	if parameters.Publish {
		q.Add("publish", "on")
	}
	if parameters.IgnoreMismatch {
		q.Add("ignoreMismatch", "on")
	}

	req.URL.RawQuery = q.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &domain.APIError{
			StatusCode: resp.StatusCode,
			Message:    resp.Status,
		}
	}

	var report domain.HostReport

	if err := json.Unmarshal(body, &report); err != nil {
		return nil, err
	}

	report.RawJSON = body

	return &report, nil
}
