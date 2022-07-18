package config

import (
	"fmt"
	"strings"

	"github.com/acorn-io/acorn/pkg/config"
	"github.com/acorn-io/acorn/pkg/dns"
	"github.com/acorn-io/acorn/pkg/labels"
	"github.com/acorn-io/acorn/pkg/system"
	"github.com/acorn-io/baaah/pkg/router"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func SetupDNS(req router.Request, resp router.Response) error {
	cfg, err := config.Get(req.Ctx, req.Client)
	if err != nil {
		return err
	}

	if strings.EqualFold(*cfg.AcornDNS, "disabled") {
		logrus.Debugf("Acorn DNS is disabled, not initializing an Acorn DNS domain")
		return nil
	}

	dnsSecret := &corev1.Secret{}
	err = req.Client.Get(req.Ctx, router.Key(system.Namespace, system.DNSSecretName), dnsSecret)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	domain := string(dnsSecret.Data["domain"])
	token := string(dnsSecret.Data["token"])

	if domain == "" || token == "" {
		if domain != "" {
			logrus.Infof("Clearing AcornDNS domain  %v", domain)
		}
		dnsClient := dns.NewClient(*cfg.AcornDNSEndpoint, "")
		domain, token, err = dnsClient.ReserveDomain()
		if err != nil {
			return fmt.Errorf("problem reserving domain: %w", err)
		}

		logrus.Infof("Obtained AcornDNS domain: %v", domain)
	}

	resp.Objects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      system.DNSSecretName,
			Namespace: system.Namespace,
			Labels: map[string]string{
				labels.AcornManaged: "true",
			},
		},
		Data: map[string][]byte{"domain": []byte(domain), "token": []byte(token)},
	})

	return nil
}
