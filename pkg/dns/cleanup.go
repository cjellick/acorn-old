package dns

import (
	"strings"

	v12 "github.com/acorn-io/acorn/pkg/apis/api.acorn.io/v1"
	"github.com/acorn-io/acorn/pkg/apis/internal.acorn.io/v1"
	"github.com/acorn-io/acorn/pkg/labels"
	"github.com/acorn-io/acorn/pkg/system"
	"github.com/acorn-io/baaah/pkg/router"
	"github.com/sirupsen/logrus"
	v14 "k8s.io/api/core/v1"
	v13 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
)

func CleanupAcornDNSEntries(appInstance *v1.AppInstance, req router.Request, containerName string, newHosts []string, cfg *v12.Config) error {
	existingIngress := v13.Ingress{}
	err := req.Get(&existingIngress, appInstance.Status.Namespace, containerName)
	if err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
		return nil
	}

	oldHosts := strings.Split(existingIngress.Annotations[labels.AcornHostnames], ",")
	if len(oldHosts) > 0 {
		oldHostMap := make(map[string]bool)
		for _, h := range oldHosts {
			oldHostMap[h] = true
		}
		for _, h := range newHosts {
			delete(oldHostMap, h)
		}
		if len(oldHostMap) > 0 {
			secret := &v14.Secret{}
			if err := req.Client.Get(req.Ctx, router.Key(system.Namespace, system.DNSSecretName), secret); err != nil {
				if errors.IsNotFound(err) {
					return nil
				}
				return err
			}
			domain := string(secret.Data["domain"])
			token := string(secret.Data["token"])
			if domain != "" && token != "" {
				for h := range oldHostMap {
					if strings.HasSuffix(h, domain) {
						dnsClient := NewClient()
						if err := dnsClient.DeleteRecord(*cfg.AcornDNSEndpoint, domain, strings.TrimSuffix(h, domain), token); err != nil {
							if IsDomainAuthError(err) {
								if err := ClearDNSToken(req.Ctx, req.Client, secret); err != nil {
									return err
								}
							}
							logrus.Warnf("Encountered an error attempting to cleanup DNS entry %v. This will not be retried. Record will eventually be cleaned up due to aging out. Error: %v", h, err)
						}
					}
				}
			}
		}
	}
	return nil
}
