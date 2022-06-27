package dns

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/acorn-io/acorn/pkg/labels"
	"github.com/sirupsen/logrus"
	"k8s.io/api/networking/v1"
)

func ToRecordRequestsAndHash(domain string, ingress *v1.Ingress) ([]RecordRequest, string) {
	var ips, lbHosts, recordValues []string

	for _, i := range ingress.Status.LoadBalancer.Ingress {
		if i.IP != "" {
			ips = append(ips, i.IP)
		}
		if i.Hostname != "" {
			lbHosts = append(lbHosts, i.Hostname)
		}
	}
	var recordType string
	if len(ips) > 0 && len(lbHosts) > 0 {
		logrus.Warnf("Cannot create DNS for ingress %v because it has both IPs and hostnames", ingress.Name)
		return nil, ""
	} else if len(ips) > 0 {
		recordType = "A"
		recordValues = ips
	} else if len(lbHosts) > 0 {
		if len(lbHosts) == 1 && lbHosts[0] == "localhost" {
			recordType = "A"
			recordValues = []string{"127.0.0.1"}
		} else {
			recordType = "CNAME"
			recordValues = lbHosts
		}
	} else {
		return nil, ""
	}

	var hosts []string
	for _, hostname := range strings.Split(ingress.Annotations[labels.AcornHostnames], ",") {
		hostname = strings.TrimSpace(hostname)
		if strings.HasSuffix(hostname, domain) {
			hosts = append(hosts, strings.TrimSuffix(hostname, domain))
		}
	}

	var requests []RecordRequest
	for _, host := range hosts {
		requests = append(requests, RecordRequest{
			Name:   host,
			Type:   RecordType(recordType),
			Values: recordValues,
		})
	}

	hash := generateHash(hosts, recordValues, recordType)
	return requests, hash
}

func generateHash(hosts, ips []string, recordType string) string {
	var toHash string
	sort.Slice(hosts, func(i, j int) bool {
		return i < j
	})
	sort.Slice(ips, func(i, j int) bool {
		return i < j
	})
	for _, h := range hosts {
		toHash += h + ","
	}
	for _, i := range ips {
		toHash += i + ","
	}
	toHash += recordType

	dig := sha1.New()
	dig.Write([]byte(toHash))
	return hex.EncodeToString(dig.Sum(nil))
}
