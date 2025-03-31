// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"slices"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"

	genericsigner "github.com/salrashid123/mtls-tokensource/signer"

	tpmsigner "github.com/salrashid123/signer/tpm"
)

var (
	cacert           = flag.String("cacert", "ca_scratchpad/ca/root-ca.crt", "RootCA")
	address          = flag.String("address", "", "Address of server")
	pubCert          = flag.String("pubCert", "ca_scratchpad/certs/workload1.crt", "Public Cert file")
	persistentHandle = flag.Uint("persistentHandle", 0x81008001, "Handle value")
	kf               = flag.String("keyfile", "ca_scratchpad/certs/workload1.pem", "Keyfile value")
	tpmPath          = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {
	flag.Parse()

	log.Printf("======= Init  ========")

	caCert, err := os.ReadFile(*cacert)
	if err != nil {
		log.Println(err)
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()
	rwr := transport.FromReadWriter(rwc)
	// pub, err := tpm2.ReadPublic{
	// 	ObjectHandle: tpm2.TPMHandle(*persistentHandle),
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("error executing tpm2.ReadPublic %v", err)
	// }

	log.Printf("======= reloading key from file ========")

	primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary TPM %q: %v", *tpmPath, err)
	}

	log.Printf(" primary key name %s\n", hex.EncodeToString(primary.Name.Buffer))

	// load the tpm-tss generated rsa key from disk
	log.Printf("======= reading key from file ========")
	c, err := os.ReadFile(*kf)
	if err != nil {
		log.Fatalf("error reading private keyfile: %v", err)
	}
	key, err := keyfile.Decode(c)
	if err != nil {
		log.Fatalf("failed decoding key: %v", err)
	}
	regenRSAKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primary.ObjectHandle,
			Name:   tpm2.TPM2BName(primary.Name),
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't load rsa key: %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: regenRSAKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	flush := tpm2.FlushContext{
		FlushHandle: primary.ObjectHandle,
	}
	_, err = flush.Execute(rwr)
	if err != nil {
		log.Fatalf("can't close primary  %v", err)
	}

	tsigner, err := tpmsigner.NewTPMCrypto(&tpmsigner.TPM{
		TpmDevice:      rwc,
		Handle:         regenRSAKey.ObjectHandle,
		PublicCertFile: *pubCert,
	})
	if err != nil {
		log.Fatal(err)
	}

	rs, err := genericsigner.NewGenericSignerTLS(&genericsigner.GenericSignerTLS{
		Signer:              tsigner,
		MtlsCertificateFile: *pubCert,
	})
	if err != nil {
		log.Fatal(err)
	}

	tcrt, err := rs.TLSCertificate()
	if err != nil {
		log.Fatal(err)
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caCertPool,
			ServerName:   "server.domain.com",
			Certificates: []tls.Certificate{tcrt},
		},
	}

	client := &http.Client{Transport: tr}

	resp, err := client.Get(fmt.Sprintf("https://%s:8443/", *address))
	if err != nil {
		log.Println(err)
		return
	}

	htmlData, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("%s\n", resp.Status)
	fmt.Printf("%s\n", string(htmlData))

}
