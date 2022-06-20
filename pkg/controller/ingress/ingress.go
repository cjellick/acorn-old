package ingress

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/acorn-io/acorn/pkg/config"
	"github.com/acorn-io/acorn/pkg/dns"
	"github.com/acorn-io/acorn/pkg/labels"
	"github.com/acorn-io/acorn/pkg/system"
	"github.com/acorn-io/baaah/pkg/router"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

func RequireLBs(h router.Handler) router.Handler {
	return router.HandlerFunc(func(req router.Request, resp router.Response) error {
		ingress := req.Object.(*netv1.Ingress)

		if len(ingress.Status.LoadBalancer.Ingress) == 0 {
			return nil
		}
		return h.Handle(req, resp)
	})
}

func SetDNS(req router.Request, resp router.Response) error {
	ingress := req.Object.(*netv1.Ingress)

	// TODO hostnames..guess we need CNAMES
	var ips []string
	for _, i := range ingress.Status.LoadBalancer.Ingress {
		if i.IP != "" {
			ips = append(ips, i.IP)
		}
	}

	if len(ips) == 0 {
		return nil
	}

	cm := &corev1.ConfigMap{}
	if err := req.Client.Get(req.Ctx, router.Key(system.Namespace, system.DNSConfigName), cm); err != nil {
		if apierrors.IsNotFound(err) {
			return nil // Config doesn't exist. Nothing we can do here.
		}
		return err
	}
	domain := cm.Data["domain"]
	token := cm.Data["token"]
	if domain == "" || token == "" {
		logrus.Warnf("DNS config map doesn't have expected entries. Domain: %v. Token: %v", domain, token)
		return nil
	}

	var hosts []string
	for _, hostname := range strings.Split(ingress.Annotations[labels.AcornHostnames], ",") {
		hostname = strings.TrimSpace(hostname)
		if hostname == "" {
			continue
		}
		if strings.HasSuffix(hostname, domain) {
			hosts = append(hosts, hostname)
		}
	}

	if len(hosts) == 0 {
		return nil
	}

	hash := generateHash(hosts, ips)

	dnsHash, ok := ingress.Annotations[labels.AcornDNSHash]
	if ok && hash == dnsHash {
		// If the hashes are the same, we've already made all the appropriate DNS entries for this ingress. Nothing to do.
		// We are doing this to avoid unnecessarily calling the external acorn-dns service.
		return nil
	}

	cfg, err := config.Get(req.Ctx, req.Client)
	if err != nil {
		return err
	}

	dnsClient := dns.NewClient(cfg.AcornDNSEndpoint)
	for _, host := range hosts {
		if err := dnsClient.CreateRecord(domain, token, host, "A", ips); err != nil {
			return err
		}
	}

	ingress.Annotations[labels.AcornDNSHash] = hash
	err = req.Client.Update(req.Ctx, ingress)
	if err != nil {
		return err
	}

	resp.Objects(ingress)
	return nil
}

func generateHash(hosts, ips []string) string {
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

	dig := sha1.New()
	dig.Write([]byte(toHash))
	return hex.EncodeToString(dig.Sum(nil))
}
