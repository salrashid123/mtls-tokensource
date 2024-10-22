package signermtls

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

const ()

type GenericSignerTLS struct {
	crypto.Signer              // https://golang.org/pkg/crypto/#Signer
	MtlsCertificateFile string // mtls x509 client cert
	x509Certificate     *x509.Certificate
	SignatureAlgorithm  x509.SignatureAlgorithm
}

// NewGenericSignerTLS constructs a singer which can be used for TLS session (eg, returns a supporting tls.Certificate)
//
//	Signer: (crypto.Signer): any crypto signer
//	MtlsCertificateFile (string): The client certificate file for mtls workload federation
func NewGenericSignerTLS(conf *GenericSignerTLS) (GenericSignerTLS, error) {

	if conf.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		conf.SignatureAlgorithm = x509.SHA256WithRSA
	}
	if (conf.SignatureAlgorithm != x509.SHA256WithRSA) && (conf.SignatureAlgorithm != x509.SHA256WithRSAPSS) && (conf.SignatureAlgorithm != x509.ECDSAWithSHA256) {
		return GenericSignerTLS{}, fmt.Errorf("signatureALgorithm must be either x509.SHA256WithRSA or x509.SHA256WithRSAPSS or x509.ECDSAWithSHA256")
	}

	if conf.Signer == nil {
		return GenericSignerTLS{}, fmt.Errorf("must specify a crypto.Signer as the Signer: parameter")
	}

	return *conf, nil
}

func (t GenericSignerTLS) TLSCertificate() (tls.Certificate, error) {

	if t.MtlsCertificateFile == "" {
		return tls.Certificate{}, fmt.Errorf("public X509 certificate not specified")
	}

	if t.x509Certificate == nil {
		pubPEM, err := os.ReadFile(t.MtlsCertificateFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("unable to read keys %v", err)
		}
		block, _ := pem.Decode([]byte(pubPEM))
		if block == nil {
			return tls.Certificate{}, fmt.Errorf("failed to parse PEM block containing the public key")
		}
		pub, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to parse public key: %v ", err)
		}
		t.x509Certificate = pub
	}

	var privKey crypto.PrivateKey = t
	return tls.Certificate{
		PrivateKey:  privKey,
		Leaf:        t.x509Certificate,
		Certificate: [][]byte{t.x509Certificate.Raw},
	}, nil
}
