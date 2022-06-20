package appdefinition

import (
	"strings"

	apiv1 "github.com/acorn-io/acorn/pkg/apis/acorn.io/v1"
	"github.com/acorn-io/acorn/pkg/labels"
	"github.com/acorn-io/baaah/pkg/router"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func addCertificates(appInstance *apiv1.AppInstance, req router.Request, resp router.Response) error {
	c := &v1.Certificate{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: appInstance.Namespace,
			Annotations: map[string]string{
				labels.AcornHostnames: strings.Join([]string{"foo"}, ","),
			},
		},
		Spec: v1.CertificateSpec{
			SecretName:  "ok",
			DNSNames:    []string{"craig.on-acorn.io"},
			IPAddresses: []string{"192.168.1.20"},
		},
	}
	resp.Objects(
		c,
	)

	return nil
}
