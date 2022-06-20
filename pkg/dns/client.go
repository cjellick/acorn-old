package dns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

const (
	contentType     = "Content-Type"
	jsonContentType = "application/json"
)

// TODO These request and response objects all need refactored and cleaned up
type DomainOpts struct {
	Namespace string              `json:"namespace"`
	Fqdn      string              `json:"fqdn"`
	Hosts     []string            `json:"hosts"`
	SubDomain map[string][]string `json:"subdomain"`
	Text      string              `json:"text"`
	CNAME     string              `json:"cname"`
}

type Domain struct {
	Domain     string              `json:"domain,omitempty"`
	Hosts      []string            `json:"hosts,omitempty"`
	SubDomain  map[string][]string `json:"subdomain,omitempty"`
	Text       string              `json:"text,omitempty"`
	CNAME      string              `json:"cname,omitempty"`
	Expiration *time.Time          `json:"expiration,omitempty"`
}

type Response struct {
	Status  int    `json:"status"`
	Message string `json:"msg"`
	Data    Domain `json:"data,omitempty"`
	Token   string `json:"token"`
}

type RecordInput struct {
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	Values []string `json:"values"`
}

type RecordOutput struct {
	RecordInput
	FQDN string `json:"fqdn"`
}

type RecordResponse struct {
	Status  int          `json:"status"`
	Message string       `json:"msg"`
	Data    RecordOutput `json:"data,omitempty"`
}

type Client interface {
	ReserveDomain() (string, string, error)
	CreateRecord(domain, token, subdomainFQDN, rType string, values []string) error
}

type dnsClient struct {
	endpoint string
	c        *http.Client
}

func (c *dnsClient) CreateRecord(domain, token, subdomainFQDN, rType string, values []string) error {
	input := &RecordInput{
		Name:   strings.TrimSuffix(subdomainFQDN, domain),
		Type:   rType,
		Values: values,
	}

	url := buildRecordsURL(c.endpoint, domain)
	body, err := jsonBody(input)
	if err != nil {
		return err
	}

	req, err := c.request(http.MethodPost, url, body)
	if err != nil {
		return err
	}

	bearer := "Bearer " + token
	req.Header.Add("Authorization", bearer)

	err = c.do(req, &RecordResponse{})
	if err != nil {
		return fmt.Errorf("failed to execute createRecord request, error: %v", err)
	}
	return nil
}

func (c *dnsClient) ReserveDomain() (string, string, error) {
	options := &DomainOpts{}

	url := buildURL(c.endpoint, "domains")
	body, err := jsonBody(options)
	if err != nil {
		return "", "", err
	}

	req, err := c.request(http.MethodPost, url, body)
	if err != nil {
		return "", "", err
	}

	resp := &Response{}
	err = c.do(req, resp)
	if err != nil {
		return "", "", fmt.Errorf("failed to reserve domain, error: %v", err)
	}

	domain := resp.Data.Domain
	if !strings.HasPrefix(domain, ".") {
		domain = "." + domain
	}
	return domain, resp.Token, err
}

func buildURL(base, path string) string {
	return fmt.Sprintf("%s/%s", base, path)
}

func buildRecordsURL(base, domain string) string {
	domain = strings.TrimPrefix(domain, ".")
	return fmt.Sprintf("%s/domains/%s/records", base, domain)
}

func (c *dnsClient) request(method string, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add(contentType, jsonContentType)

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

	err = json.Unmarshal(body, responseBody)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response body (%v), error: %v", string(body), err)
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

func NewClient(endpoint string) Client {
	return &dnsClient{
		endpoint: endpoint,
		c:        http.DefaultClient,
	}
}
