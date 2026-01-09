//go:build testing

package testing

import (
	"crypto"
	"crypto/x509"

	"github.com/zoobzio/sctx"
)

// CreateAssertion is a convenience function to create assertions for testing.
func CreateAssertion(privateKey crypto.PrivateKey, cert *x509.Certificate) (sctx.SignedAssertion, error) {
	return sctx.CreateAssertion(privateKey, cert)
}
