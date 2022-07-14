package ingress

import (
	"github.com/acorn-io/acorn/pkg/config"
	"github.com/acorn-io/acorn/pkg/dns"
	"github.com/acorn-io/acorn/pkg/labels"
	"github.com/acorn-io/acorn/pkg/system"
	"github.com/acorn-io/baaah/pkg/router"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/strings/slices"
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
	cfg, err := config.Get(req.Ctx, req.Client)
	if err != nil {
		return err
	}

	secret := &corev1.Secret{}
	if err := req.Client.Get(req.Ctx, router.Key(system.Namespace, system.DNSSecretName), secret); err != nil {
		if apierrors.IsNotFound(err) {
			// DNS Secret doesn't exist. Nothing to do
			return nil
		}
		return err
	}
	domain := string(secret.Data["domain"])
	token := string(secret.Data["token"])
	if domain == "" || token == "" {
		logrus.Warnf("DNS secret doesn't have expected entries. Domain: %v.", domain)
		return nil
	}

	ingress := req.Object.(*netv1.Ingress)
	var hash string
	var requests []dns.RecordRequest
	if slices.Contains(cfg.ClusterDomains, domain) {
		requests, hash = dns.ToRecordRequestsAndHash(domain, ingress)
		if len(requests) == 0 {
			return nil
		}

		if hash == ingress.Annotations[labels.AcornDNSHash] {
			// If the hashes are the same, we've already made all the appropriate DNS entries for this ingress.
			return nil
		}

		dnsClient := dns.NewClient(*cfg.AcornDNSEndpoint, token)
		if err := dnsClient.CreateRecords(domain, requests); err != nil {
			return err
		}
	}

	if hash != ingress.Annotations[labels.AcornDNSHash] {
		ingress.Annotations[labels.AcornDNSHash] = hash
		err = req.Client.Update(req.Ctx, ingress)
		if err != nil {
			return err
		}
		resp.Objects(ingress)
	}

	return nil
}
