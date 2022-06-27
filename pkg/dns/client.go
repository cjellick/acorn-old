package dns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	contentType     = "Content-Type"
	jsonContentType = "application/json"
)

type Client interface {
	ReserveDomain() (string, string, error)
	CreateRecords(domain string, records []RecordRequest) error
	Renew(domain string, renew RenewRequest) (RenewResponse, error)
	DeleteRecord(domain, fqdn string) error
}

func NewClient(endpoint, token string) Client {
	return &dnsClient{
		endpoint: endpoint,
		token:    token,
		c:        http.DefaultClient,
	}
}

type dnsClient struct {
	endpoint string
	token    string
	c        *http.Client
}

func (c *dnsClient) CreateRecords(domain string, records []RecordRequest) error {
	url := fmt.Sprintf("%s/domains/%s/records", c.endpoint, domain)

	for _, recordRequest := range records {
		body, err := jsonBody(recordRequest)
		if err != nil {
			return err
		}

		req, err := c.request(http.MethodPost, url, body, true)
		if err != nil {
			return err
		}

		err = c.do(req, &RecordResponse{})
		if err != nil {
			return fmt.Errorf("failed to execute createRecord request, error: %v", err)
		}
	}
	return nil
}

func (c *dnsClient) Renew(domain string, renew RenewRequest) (RenewResponse, error) {
	url := fmt.Sprintf("%v/domains/%v/renew", c.endpoint, domain)
	body, err := jsonBody(renew)
	if err != nil {
		return RenewResponse{}, err
	}

	req, err := c.request(http.MethodPost, url, body, true)
	if err != nil {
		return RenewResponse{}, err
	}

	resp := RenewResponse{}
	err = c.do(req, &resp)
	if err != nil {
		return RenewResponse{}, fmt.Errorf("failed to execute renew request, error: %v", err)
	}
	return resp, nil
}

func (c *dnsClient) ReserveDomain() (string, string, error) {
	url := fmt.Sprintf("%s/%s", c.endpoint, "domains")

	req, err := c.request(http.MethodPost, url, nil, false)
	if err != nil {
		return "", "", err
	}

	resp := &DomainResponse{}
	err = c.do(req, resp)
	if err != nil {
		return "", "", fmt.Errorf("failed to reserve domain, error: %v", err)
	}

	domain := resp.Name
	if !strings.HasPrefix(domain, ".") {
		domain = "." + domain
	}
	return domain, resp.Token, err
}

func (c *dnsClient) DeleteRecord(domain, prefix string) error {
	url := fmt.Sprintf("%v/domains/%v/records/%v", c.endpoint, domain, prefix)

	req, err := c.request(http.MethodDelete, url, nil, true)
	if err != nil {
		return err
	}

	err = c.do(req, nil)
	if err != nil {
		return fmt.Errorf("failed to execute delete request, error: %v", err)
	}
	return nil
}

func (c *dnsClient) request(method string, url string, body io.Reader, auth bool) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add(contentType, jsonContentType)

	if auth {
		bearer := "Bearer " + c.token
		req.Header.Add("Authorization", bearer)
	}

	return req, nil
}

func (c *dnsClient) do(req *http.Request, responseBody interface{}) error {
	resp, err := c.c.Do(req)
	if err != nil {
		return err
	}
	// when err is nil, resp contains a non-nil resp.Body which must be closed
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body, error: %v", err)
	}

	if responseBody != nil {
		err = json.Unmarshal(body, responseBody)
		if err != nil {
			return fmt.Errorf("failed to unmarshal response body (%v), error: %v", string(body), err)
		}
	}

	if code := resp.StatusCode; code < 200 || code > 300 {
		return fmt.Errorf("unexpected response status code: %v", code)
	}

	return nil
}

func jsonBody(payload interface{}) (io.Reader, error) {
	buf := &bytes.Buffer{}
	err := json.NewEncoder(buf).Encode(payload)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
