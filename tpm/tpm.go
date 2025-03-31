package tpmmtls

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"
	tpmSigner "github.com/salrashid123/signer/tpm"
	"golang.org/x/net/http2"
	"golang.org/x/oauth2"
)

const (
	GCP_STS_MTLS_ENDPOINT    = "https://sts.mtls.googleapis.com/v1/token"
	MTLS_SUBJECT_TOKEN_TYPE  = "urn:ietf:params:oauth:token-type:mtls"
	REQUESTED_TOKEN_TYPE     = "urn:ietf:params:oauth:token-type:access_token"
	GRANT_TYPE               = "urn:ietf:params:oauth:grant-type:token-exchange"
	GCP_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
)

// TpmTokenConfig parameters to start Credential based off of TPM RSA Private Key.
type TpmMtlsTokenConfig struct {
	TPMDevice           io.ReadWriteCloser
	Handle              tpm2.TPMHandle // load a key from handle
	AuthSession         tpmjwt.Session
	Scopes              []string
	Audience            string         // for mtls workload federation
	MtlsCertificateFile string         // mtls x509 client cert
	EncryptionHandle    tpm2.TPMHandle // (optional) handle to use for transit encryption
}

type tpmMtlsTokenSource struct {
	refreshMutex *sync.Mutex
	oauth2.TokenSource
	audience            string
	mtlsCertificateFile string
	tpmdevice           io.ReadWriteCloser
	handle              tpm2.TPMHandle
	authSession         tpmjwt.Session
	scopes              []string
	myToken             *oauth2.Token
	encryptionHandle    tpm2.TPMHandle // (optional) handle to use for transit encryption
}

type rtokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type sTSTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// TpmMTLSTokenSource returns a TokenSource or GCP workload federation using mTLS where the key is in a TPM
//
//	TPMDevice (io.ReadWriteCloser): The device Handle for the TPM managed by the caller Use either TPMDevice or TPMPath
//	Audience (string): The audience for mtls workload federation
//	mtlsCertificateFile (string): The client certificate file for mtls workload federation
//	Scopes ([]string): The GCP Scopes for the GCP token. (default: cloud-platform)
//	NamedHandle (*tpm2.NameHandle): The key handle to use
//	AuthSession: (go-tpm-jwt.Session): PCR or Password authorized session to use (github.com/salrashid123/golang-jwt-tpm)
func TpmMTLSTokenSource(tokenConfig *TpmMtlsTokenConfig) (oauth2.TokenSource, error) {

	if &tokenConfig.Handle == nil || tokenConfig.TPMDevice == nil {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: KeyHandle and TPMDevice must be specified")
	}

	if tokenConfig.Audience == "" {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: e TPMTokenConfig.Audience and cannot be nil")
	}

	if tokenConfig.Audience != "" && tokenConfig.MtlsCertificateFile == "" {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: TPMTokenConfig.Audience and tokenConfig.MtlsCertificateFile must be set")
	}

	if len(tokenConfig.Scopes) == 0 {
		tokenConfig.Scopes = []string{GCP_CLOUD_PLATFORM_SCOPE}
	}

	return &tpmMtlsTokenSource{
		refreshMutex:        &sync.Mutex{},
		audience:            tokenConfig.Audience,
		mtlsCertificateFile: tokenConfig.MtlsCertificateFile,
		tpmdevice:           tokenConfig.TPMDevice,
		authSession:         tokenConfig.AuthSession,
		scopes:              tokenConfig.Scopes,
		handle:              tokenConfig.Handle,
		encryptionHandle:    tokenConfig.EncryptionHandle,
	}, nil

}

func (ts *tpmMtlsTokenSource) Token() (*oauth2.Token, error) {
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

	r, err := tpmSigner.NewTPMCrypto(&tpmSigner.TPM{
		TpmDevice:      ts.tpmdevice,
		Handle:         ts.handle,
		PublicCertFile: ts.mtlsCertificateFile,
	})
	if err != nil {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: error initializing client, %v", err)
	}

	sslKeyLogfile := os.Getenv("SSLKEYLOGFILE")
	var w *os.File
	if sslKeyLogfile != "" {
		w, err = os.OpenFile(sslKeyLogfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			panic(err)
		}
	} else {
		w = os.Stdout
	}

	tcrt, err := r.TLSCertificate()
	if err != nil {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: error reading client certificate %v", err)
	}
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			//RootCAs: caCertPool,
			//ServerName:   "sts.mtls.googleapis.com",
			Certificates: []tls.Certificate{tcrt},
			KeyLogWriter: w,
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
