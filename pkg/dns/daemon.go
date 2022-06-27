package dns

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/acorn-io/acorn/pkg/config"
	"github.com/acorn-io/acorn/pkg/labels"
	"github.com/acorn-io/acorn/pkg/system"
	"github.com/acorn-io/baaah/pkg/router"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	klabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type Daemon struct {
	client kclient.Client
	ctx    context.Context
}

func NewDaemon(ctx context.Context, client kclient.Client) *Daemon {
	return &Daemon{
		client: client,
		ctx:    ctx,
	}
}

// RenewAndSync will renew the cluster's Acorn DNS domain and corresponding records.
// It sends each ingress's full record (fqdn, type, values). In addition to renewing the records, the DNS service will
// return "out of sync" records that either don't exist or have different values on the DNS service side. This function
// will cause the ingresses for such records to resync.
//
// Retries on an exponential backoff until successful
func (d *Daemon) RenewAndSync(ctx context.Context) {
	err := wait.ExponentialBackoffWithContext(ctx, wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   2,
		Steps:    10,
		Cap:      300 * time.Second,
	}, d.internal)
	if err != nil {
		logrus.Errorf("Couldn't complete RenewAndSync: %v", err)
	}
}

func (d *Daemon) internal() (bool, error) {
	logrus.Debugf("Renewing and syncing Acorn DNS")
	cfg, err := config.Get(d.ctx, d.client)
	if err != nil {
		logrus.Errorf("Failed to get config: %v", err)
		return false, nil
	}

	if strings.EqualFold(*cfg.AcornDNS, "disabled") {
		logrus.Debugf("Acorn DNS is disabled, not attempting DNS renewal")
		return true, nil
	}

	dnsSecret := &corev1.Secret{}
	err = d.client.Get(d.ctx, router.Key(system.Namespace, system.DNSSecretName), dnsSecret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			logrus.Infof("DNS secret %v/%v not found, not proceeding with DNS renewal", system.Namespace, system.DNSSecretName)
			return true, nil
		}
		logrus.Errorf("Problem getting DNS secret %v/%v: %v", system.Namespace, system.DNSSecretName, err)
		return false, nil
	}

	var domain, token string
	domain = string(dnsSecret.Data["domain"])
	token = string(dnsSecret.Data["token"])
	if domain == "" || token == "" {
		return false, fmt.Errorf("dns secret %v/%v exists but is missing domain or token. Aborting", system.Namespace, system.DNSSecretName)
	}

	var ingresses netv1.IngressList
	err = d.client.List(d.ctx, &ingresses, &kclient.ListOptions{
		LabelSelector: klabels.SelectorFromSet(map[string]string{
			labels.AcornManaged: "true",
		}),
	})
	if err != nil {
		logrus.Errorf("Failed to list ingresses for DNS renewal: %v", err)
		return false, nil
	}

	var recordRequests []RecordRequest
	ingressMap := make(map[FQDNTypePair]netv1.Ingress)
	for _, ingress := range ingresses.Items {
		rrs, _ := ToRecordRequestsAndHash(domain, &ingress)
		recordRequests = append(recordRequests, rrs...)
		for _, r := range rrs {
			ingressMap[FQDNTypePair{FQDN: r.Name, Type: string(r.Type)}] = ingress
		}
	}

	dnsClient := NewClient(*cfg.AcornDNSEndpoint, token)
	response, err := dnsClient.Renew(domain, RenewRequest{Records: recordRequests})
	if err != nil {
		logrus.Errorf("Failed to call DNS renew API: %v", err)
		return false, nil
	}

	for _, outOfSync := range response.OutOfSyncRecords {
		i, ok := ingressMap[outOfSync]
		if ok {
			delete(i.Annotations, labels.AcornDNSHash)
			err = d.client.Update(d.ctx, &i)
			if err != nil {
				logrus.Errorf("Problem updating ingress %v: %v", i.Name, err)
				return false, nil
			}
		}
	}

	return true, nil
}
