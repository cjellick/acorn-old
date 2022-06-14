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

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	contentType     = "Content-Type"
	jsonContentType = "application/json"
)

type DomainOpts struct {
	Namespace string              `json:"namespace"`
	Fqdn      string              `json:"fqdn"`
	Hosts     []string            `json:"hosts"`
	SubDomain map[string][]string `json:"subdomain"`
	Text      string              `json:"text"`
	CNAME     string              `json:"cname"`
}

type Domain struct {
	Fqdn       string              `json:"fqdn,omitempty"`
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

type Client interface {
	CreateDomain(namespace string) (string, string, error)
	ReserveDomain() (string, string, error)
}

type dnsClient struct {
	endpoint string
	c        *http.Client
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
		return "", "", errors.Wrap(err, "CreateDomain: failed to build a request")
	}

	resp, err := c.do(req)
	if err != nil {
		return "", "", errors.Wrap(err, "CreateDomain: failed to execute a request")
	}
	domain := resp.Data.Fqdn
	if !strings.HasPrefix(domain, ".") {
		domain = "." + domain
	}
	return domain, resp.Token, err
}

func (c *dnsClient) CreateDomain(namespace string) (string, string, error) {
	options := &DomainOpts{
		Namespace: namespace,
	}

	url := buildURL(c.endpoint, "domains")
	body, err := jsonBody(options)
	if err != nil {
		return "", "", err
	}

	req, err := c.request(http.MethodPost, url, body)
	if err != nil {
		return "", "", errors.Wrap(err, "CreateDomain: failed to build a request")
	}

	resp, err := c.do(req)
	if err != nil {
		return "", "", errors.Wrap(err, "CreateDomain: failed to execute a request")
	}

	return resp.Data.Fqdn, resp.Token, err
}

//buildUrl return request url
func buildURL(base, path string) string {
	return fmt.Sprintf("%s/%s", base, path)
}

func (c *dnsClient) request(method string, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add(contentType, jsonContentType)

	return req, nil
}

func (c *dnsClient) do(req *http.Request) (Response, error) {
	var data Response
	resp, err := c.c.Do(req)
	if err != nil {
		return data, err
	}
	// when err is nil, resp contains a non-nil resp.Body which must be closed
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return data, errors.Wrap(err, "read Response body error")
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		return data, errors.Wrapf(err, "decode Response error: %s", string(body))
	}
	logrus.Debugf("got Response entry: %+v", data)
	if code := resp.StatusCode; code < 200 || code > 300 {
		if data.Message != "" {
			return data, errors.Errorf("got request error: %s", data.Message)
		}
	}

	return data, nil
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
