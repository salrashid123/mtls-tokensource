package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"cloud.google.com/go/storage"
	tpmmtls "github.com/salrashid123/mtls-tokensource/tpm"
)

var (
	//cacert = flag.String("cacert", "ca_scratchpad/ca/root-ca.crt", "RootCA")

	pubCert          = flag.String("pubCert", "ca_scratchpad/certs/workload1.crt", "Public Cert file")
	persistentHandle = flag.Uint("persistentHandle", 0x81008001, "Handle value")
	kf               = flag.String("keyfile", "ca_scratchpad/certs/workload1.pem", "Keyfile value")
	tpmPath          = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	projectId        = flag.String("projectId", "core-eso", "ProjectID")
	projectNumber    = flag.String("projectNumber", "995081019036", "ProjectNumber")
	poolid           = flag.String("poolid", "cert-pool-1", "Workload PoolID")
	providerid       = flag.String("providerid", "cert-provider-1", "Workload providerid")
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

	// caCert, err := os.ReadFile(*cacert)
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }
	//caCertPool := x509.NewCertPool()
	//caCertPool.AppendCertsFromPEM(caCert)

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

	certPEMBlock, err := os.ReadFile(*pubCert)
	if err != nil {
		log.Fatalf("Failed to read certificate file: %v", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(certPEMBlock)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatal("Failed to decode PEM block as certificate")
	}

	// Parse the X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}

	ts, err := tpmmtls.TpmMTLSTokenSource(&tpmmtls.TpmMtlsTokenConfig{
		TPMDevice:       rwc,
		Handle:          regenRSAKey.ObjectHandle,
		Audience:        fmt.Sprintf("//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s", *projectNumber, *poolid, *providerid),
		X509Certificate: cert,
	})
	if err != nil {
		log.Fatal(err)
	}
	tok, err := ts.Token()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Token: %v", tok.AccessToken)

	ctx := context.Background()

	storageClient, err := storage.NewClient(ctx, option.WithTokenSource(ts))
	if err != nil {
		log.Fatal(err)
	}
	sit := storageClient.Buckets(ctx, *projectId)
	for {
		battrs, err := sit.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		log.Printf(battrs.Name)
	}

}
