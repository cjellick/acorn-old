package dns

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

// Client handles interactions with the AcornDNS API service and Acorn.
type Client interface {

	// ReserveDomain calls AcornDNS to reserve a new domain. It returns the domain, a token for authentication,
	// and an error
	ReserveDomain() (string, string, error)

	// CreateRecords calls AcornDNS to create dns records based on the supplied RecordRequests for the specified domain
	CreateRecords(domain, token string, records []RecordRequest) error

	// Renew calls AcornDNS to renew the domain and the records specified in the renewRequest. The response will contain
	// "out of sync" records, which are records that AcornDNS either doesn't know about or has different values for
	Renew(domain, token string, renew RenewRequest) (RenewResponse, error)

	// DeleteRecord calls AcornDNS to delete the record(s) associated with the supplied fqdn
	DeleteRecord(domain, fqdn, token string) error
}

// AuthFailedNoDomainError indicates that a request failed authentication because the domain was not found. If encountered,
// we'll need to reserve a new domain.
type AuthFailedNoDomainError struct{}

// Error implements the Error interface
func (e AuthFailedNoDomainError) Error() string {
	return "the supplied domain failed authentication"
}

// IsDomainAuthError checks if the error is a DomainAuthError
func IsDomainAuthError(err error) bool {
	return errors.Is(err, AuthFailedNoDomainError{})
}

// NewClient creates a new AcornDNS client
func NewClient(endpoint string) Client {
	return &client{
		endpoint: endpoint,
		c:        http.DefaultClient,
	}
}

type client struct {
	endpoint string
	c        *http.Client
}

func (c *client) CreateRecords(domain, token string, records []RecordRequest) error {
	url := fmt.Sprintf("%s/domains/%s/records", c.endpoint, domain)

	for _, recordRequest := range records {
		body, err := jsonBody(recordRequest)
		if err != nil {
			return err
		}

		req, err := c.request(http.MethodPost, url, body, token)
		if err != nil {
			return err
		}

		err = c.do(req, &RecordResponse{})
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *client) Renew(domain, token string, renew RenewRequest) (RenewResponse, error) {
	url := fmt.Sprintf("%v/domains/%v/renew", c.endpoint, domain)
	body, err := jsonBody(renew)
	if err != nil {
		return RenewResponse{}, err
	}

	req, err := c.request(http.MethodPost, url, body, token)
	if err != nil {
		return RenewResponse{}, err
	}

	resp := RenewResponse{}
	err = c.do(req, &resp)
	if err != nil {
		return RenewResponse{}, fmt.Errorf("failed to execute renew request, error: %w", err)
	}
	return resp, nil
}

func (c *client) ReserveDomain() (string, string, error) {
	url := fmt.Sprintf("%s/%s", c.endpoint, "domains")

	req, err := c.request(http.MethodPost, url, nil, "")
	if err != nil {
		return "", "", err
	}

	resp := &DomainResponse{}
	err = c.do(req, resp)
	if err != nil {
		return "", "", fmt.Errorf("failed to reserve domain, error: %w", err)
	}

	domain := resp.Name
	if !strings.HasPrefix(domain, ".") {
		domain = "." + domain
	}
	return domain, resp.Token, err
}

func (c *client) DeleteRecord(domain, prefix, token string) error {
	url := fmt.Sprintf("%v/domains/%v/records/%v", c.endpoint, domain, prefix)

	req, err := c.request(http.MethodDelete, url, nil, token)
	if err != nil {
		return err
	}

	err = c.do(req, nil)
	if err != nil {
		return fmt.Errorf("failed to execute delete request, error: %w", err)
	}
	return nil
}

func (c *client) request(method string, url string, body io.Reader, token string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	if token != "" {
		bearer := "Bearer " + token
		req.Header.Add("Authorization", bearer)
	}

	return req, nil
}

func (c *client) do(req *http.Request, responseBody interface{}) error {
	resp, err := c.c.Do(req)
	if err != nil {
		return err
	}
	// when err is nil, resp contains a non-nil resp.Body which must be closed
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body, error: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		var authError AuthErrorResponse

		err = json.Unmarshal(body, &authError)
		if err != nil {
			return fmt.Errorf("failed to unmarshal error response, error: %w", err)
		}

		if authError.Data.NoDomain {
			return AuthFailedNoDomainError{}
		}

		return fmt.Errorf("authentication failed")
	}

	if code := resp.StatusCode; code < 200 || code > 300 {
		return fmt.Errorf("unexpected response status code: %v", code)
	}

	if responseBody != nil {
		err = json.Unmarshal(body, responseBody)
		if err != nil {
			return fmt.Errorf("failed to unmarshal response body (%v), error: %w", string(body), err)
		}
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
