package signermtls

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/oauth2"
)

var ()

const (
	GCP_STS_MTLS_ENDPOINT    = "https://sts.mtls.googleapis.com/v1/token"
	MTLS_SUBJECT_TOKEN_TYPE  = "urn:ietf:params:oauth:token-type:mtls"
	REQUESTED_TOKEN_TYPE     = "urn:ietf:params:oauth:token-type:access_token"
	GRANT_TYPE               = "urn:ietf:params:oauth:grant-type:token-exchange"
	GCP_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
)

// TpmTokenConfig parameters to start Credential based off of TPM RSA Private Key.
type SignerMtlsTokenConfig struct {
	Signer     crypto.Signer
	Scopes     []string
	Audience   string            // for mtls workload federation
	PublicCert *x509.Certificate // mtls x509 client cert
}

type signerMtlsTokenSource struct {
	refreshMutex *sync.Mutex
	oauth2.TokenSource
	audience            string
	mtlsCertificateFile *x509.Certificate
	signer              crypto.Signer
	scopes              []string
	myToken             *oauth2.Token
}

type sTSTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// SignerMTLSTokenSource returns a TokenSource or GCP workload federation using mTLS where the key is in a TPM
//
//	Signer (cypto.Signer): Anything that implements Signer
//	Audience (string): The audience for mtls workload federation
//	PublicCertFile (string): The client certificate file for mtls workload federation
//	Scopes ([]string): The GCP Scopes for the GCP token. (default: cloud-platform)
func SignerMTLSTokenSource(tokenConfig *SignerMtlsTokenConfig) (oauth2.TokenSource, error) {

	if tokenConfig.Signer == nil {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: Signer must be specified")
	}

	if tokenConfig.Audience == "" {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: e TPMTokenConfig.Audience and cannot be nil")
	}

	if tokenConfig.Audience != "" && tokenConfig.PublicCert == nil {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: TPMTokenConfig.Audience and tokenConfig.PublicCertFile must be set")
	}

	if len(tokenConfig.Scopes) == 0 {
		tokenConfig.Scopes = []string{GCP_CLOUD_PLATFORM_SCOPE}
	}

	return &signerMtlsTokenSource{
		refreshMutex:        &sync.Mutex{},
		audience:            tokenConfig.Audience,
		mtlsCertificateFile: tokenConfig.PublicCert,
		signer:              tokenConfig.Signer,
		scopes:              tokenConfig.Scopes,
	}, nil

}

func (ts *signerMtlsTokenSource) Token() (*oauth2.Token, error) {
	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()
	if ts.myToken.Valid() {
		return ts.myToken, nil
	}

	// todo, read in custom ca
	// caCert, err := os.ReadFile(*cacert)
	// if err != nil {
	// 	return nil, fmt.Errorf("unable to reading root trust ca %v", err)
	// }
	//caCertPool := x509.NewCertPool()
	// caCertPool.AppendCertsFromPEM(caCert)

	s, err := NewGenericSignerTLS(&GenericSignerTLS{
		MtlsCertificateFile: ts.mtlsCertificateFile,
		Signer:              ts.signer,
	})
	if err != nil {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: error initializing client, %v", err)
	}

	tcrt, err := s.TLSCertificate()
	if err != nil {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: error reading client certificate %v", err)
	}
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			//RootCAs: caCertPool,
			//ServerName:   "sts.mtls.googleapis.com",
			Certificates: []tls.Certificate{tcrt},
		},
	}

	client := &http.Client{Transport: tr}

	gform := url.Values{}
	gform.Add("grant_type", GRANT_TYPE)
	gform.Add("audience", ts.audience)
	gform.Add("subject_token_type", MTLS_SUBJECT_TOKEN_TYPE)
	gform.Add("requested_token_type", REQUESTED_TOKEN_TYPE)
	gform.Add("scope", strings.Join(ts.scopes, " "))

	gcpSTSResp, err := client.PostForm(GCP_STS_MTLS_ENDPOINT, gform)
	if err != nil {
		return nil, fmt.Errorf("error posting to sts server %v", err)
	}
	defer gcpSTSResp.Body.Close()

	if gcpSTSResp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(gcpSTSResp.Body)
		if err != nil {
			return nil, fmt.Errorf("Error reading sts response body %v", err)
		}
		return nil, fmt.Errorf("Unable to exchange token %s,  %v", string(bodyBytes), err)
	}
	tresp := &sTSTokenResponse{}
	err = json.NewDecoder(gcpSTSResp.Body).Decode(tresp)
	if err != nil {
		return nil, err
	}

	exp := time.Now().Add(time.Duration(tresp.ExpiresIn))

	ts.myToken = &oauth2.Token{AccessToken: tresp.AccessToken, TokenType: tresp.TokenType, Expiry: exp}
	return ts.myToken, nil
}
