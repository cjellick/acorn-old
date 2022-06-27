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
	// This could be a bit more robust to handle the scenario where the the reserved domain has aged out on the DNS
	// side because the cluster hasn't checked in in 30 days. We would have to delete the secret and reserve a new domain
	// in that case. But I want to wait until we see how this is used before implementing that.

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
	if !apierrors.IsNotFound(err) {
		// Either err is nil because we found the secret, or we hit some error other than it not existing. Return
		return err
	}

	dnsClient := dns.NewClient(*cfg.AcornDNSEndpoint, "")
	domain, token, err := dnsClient.ReserveDomain()
	if err != nil {
		return fmt.Errorf("problem reserving domain: %v", err)
	}

	err = req.Client.Create(req.Ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      system.DNSSecretName,
			Namespace: system.Namespace,
			Labels: map[string]string{
				labels.AcornManaged: "true",
			},
		},
		Data: map[string][]byte{"domain": []byte(domain), "token": []byte(token)},
	})
	if err != nil {
		return fmt.Errorf("problem persisting domain %v as secret %v/%v: %v", domain, system.Namespace, system.DNSSecretName, err)
	}

	logrus.Infof("Reserved domain: %v", domain)
	return nil
}
