package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	//"net/http/httputil"

	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
)

var (
	cacert     = flag.String("cacert", "ca_scratchpad/ca/root-ca.crt", "RootCA")
	servercert = flag.String("servercert", "ca_scratchpad/certs/server.crt", "Server Cert")
	serverkey  = flag.String("serverkey", "ca_scratchpad/certs/server.key", "Server Key")
)

const ()

func eventsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("CipherSuite %v TLS_AES_128_GCM_SHA256 %v\n", r.TLS.CipherSuite, tls.TLS_AES_128_GCM_SHA256)
		for _, cert := range r.TLS.PeerCertificates {
			fmt.Printf("Issuer Name: %s\n", cert.Issuer)
			fmt.Printf("Expiry: %s \n", cert.NotAfter.Format("2006-January-02"))
			fmt.Printf("Common Name: %s \n", cert.Subject.CommonName)
			fmt.Printf("IsCA: %t \n", cert.IsCA)

			hasher := sha256.New()
			hasher.Write(cert.Raw)
			clientCertificateHash := base64.StdEncoding.EncodeToString(hasher.Sum(nil))

			fmt.Printf("Certificate hash %s\n", clientCertificateHash)
			fmt.Println()

		}

		for _, cert := range r.TLS.VerifiedChains {
			for _, c := range cert {
				fmt.Printf("VerifiedChains Issuer Name: %s\n", c.Issuer)
				fmt.Printf("VerifiedChains Expiry: %s \n", c.NotAfter.Format("2006-January-02"))
				fmt.Printf("VerifiedChains Subject Common Name: %s \n", c.Subject.CommonName)
				fmt.Printf("VerifiedChains IsCA: %t \n", c.IsCA)
				h := sha256.New()
				h.Write(c.Raw)
				clientCertificateHash := base64.StdEncoding.EncodeToString(h.Sum(nil))

				fmt.Printf("VerifiedChains Certificate hash %s\n", clientCertificateHash)
				fmt.Println()
			}
		}

		h.ServeHTTP(w, r)
	})
}

func gethandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "ok")
}

func posthandler(w http.ResponseWriter, r *http.Request) {

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading body: %v", err)
		http.Error(w, "can't read body", http.StatusBadRequest)
		return
	}
	log.Printf("Data val [%s]", string(body))

	fmt.Fprint(w, "ok")
}

func main() {

	flag.Parse()

	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/").HandlerFunc(gethandler)
	router.Methods(http.MethodPost).Path("/").HandlerFunc(posthandler)

	var err error
	clientCaCert, err := os.ReadFile(*cacert)
	if err != nil {
		panic(err)
	}
	clientCaCertPool := x509.NewCertPool()
	clientCaCertPool.AppendCertsFromPEM(clientCaCert)

	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCaCertPool,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		MinVersion: tls.VersionTLS13,
	}

	server := &http.Server{
		Addr:      ":8443",
		Handler:   eventsMiddleware(router),
		TLSConfig: tlsConfig,
	}
	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")
	err = server.ListenAndServeTLS(*servercert, *serverkey)
	fmt.Printf("Unable to start Server %v", err)

}
