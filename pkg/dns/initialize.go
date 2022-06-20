package dns

import (
	"context"

	"github.com/acorn-io/acorn/pkg/config"
	"github.com/acorn-io/acorn/pkg/labels"
	"github.com/acorn-io/acorn/pkg/system"
	"github.com/acorn-io/baaah/pkg/router"
	corev1 "k8s.io/api/core/v1"
	apierror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func InitializeDomain(ctx context.Context, c client.Client) error {
	cfg, err := config.Get(ctx, c)
	if err != nil {
		return err
	}

	// User provided their own domain, don't use acorn-dns
	if len(cfg.ClusterDomains) > 0 {
		return nil
	}

	cm := &corev1.ConfigMap{}
	err = c.Get(ctx, router.Key(system.Namespace, system.DNSConfigName), cm)
	if err != nil && !apierror.IsNotFound(err) {
		return err
	} else if apierror.IsNotFound(err) {
		dnsClient := NewClient(cfg.AcornDNSEndpoint)
		domain, token, err := dnsClient.ReserveDomain()
		if err != nil {
			return err
		}

		err = c.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      system.DNSConfigName,
				Namespace: system.Namespace,
				Labels: map[string]string{
					labels.AcornManaged: "true",
				},
			},
			Data: map[string]string{"domain": domain, "token": token},
		})
		if err != nil {
			return err
		}
	}

	return nil
}
