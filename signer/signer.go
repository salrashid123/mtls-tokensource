package signermtls

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

const ()

type GenericSignerTLS struct {
	crypto.Signer       // https://golang.org/pkg/crypto/#Signer
	MtlsCertificateFile *x509.Certificate
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

	if t.MtlsCertificateFile == nil {
		return tls.Certificate{}, fmt.Errorf("public X509 certificate not specified")
	}

	var privKey crypto.PrivateKey = t
	return tls.Certificate{
		PrivateKey:  privKey,
		Leaf:        t.MtlsCertificateFile,
		Certificate: [][]byte{t.MtlsCertificateFile.Raw},
	}, nil
}
