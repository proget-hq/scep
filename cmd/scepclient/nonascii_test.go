package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"

	"github.com/micromdm/scep/v2/envelope/envelopetest"
)

// crypto/x509 refuses requests and certificates whose subjectAltName holds an
// rfc822Name, dNSName or URI that is not ASCII, which OpenSSL writes as given
// and sscep sends and stores. scepclient reads them with x509util.

// nonASCIISAN is a subjectAltName with an rfc822Name and a dNSName that are not
// ASCII, written as OpenSSL writes "email.1 = …" and "DNS.1 = …" of a config.
func nonASCIISAN(t *testing.T) pkix.Extension {
	t.Helper()
	value, err := asn1.Marshal([]asn1.RawValue{
		{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte("zażółć@example.com")},
		{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("gęś.example.com")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: value}
}

func TestLoadCSRWithNonASCIISAN(t *testing.T) {
	key := newTestKey(t)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: "client", Organization: []string{"Proget"}},
		ExtraExtensions: []pkix.Extension{nonASCIISAN(t)},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseCertificateRequest(der); err == nil {
		t.Fatal("crypto/x509 accepts the request, the case does not test anything")
	}

	path := filepath.Join(t.TempDir(), "csr.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: csrPEMBlockType, Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	csr, err := loadCSRfromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(csr.Raw, der) {
		t.Error("Raw is not the request")
	}
	if pub, ok := csr.PublicKey.(*rsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		t.Errorf("PublicKey = %v, want the key of the request", csr.PublicKey)
	}
	if got := csr.Subject.Organization; len(got) != 1 || got[0] != "Proget" {
		t.Errorf("Subject.Organization = %q, want [Proget]", got)
	}

	// what run does with it
	if _, err := selfSign(key, csr); err != nil {
		t.Fatal(err)
	}
}

// TestLoadOrMakeCSR checks the request made on the first run is the one loaded
// on the next.
func TestLoadOrMakeCSR(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csr.pem")
	opts := &csrOptions{
		cn:       "client",
		org:      "Proget",
		dnsNames: []string{"client.example.com"},
		key:      newTestKey(t),
	}
	made, err := loadOrMakeCSR(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loadOrMakeCSR(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(made.Raw, loaded.Raw) {
		t.Error("the loaded request is not the one made")
	}
	if made.Subject.String() != loaded.Subject.String() || strings.Join(made.DNSNames, ",") != strings.Join(loaded.DNSNames, ",") {
		t.Errorf("loaded %s %q, made %s %q", loaded.Subject, loaded.DNSNames, made.Subject, made.DNSNames)
	}
}

func TestLoadOrMakeCSRReportsCreateErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csr.pem")
	_, err := loadOrMakeCSR(path, &csrOptions{
		cn:       "client",
		dnsNames: []string{"gęś.example.com"},
		key:      newTestKey(t),
	})
	if err == nil {
		t.Fatal("expected an error for a dNSName crypto/x509 cannot write")
	}
}

// newIssuedWithNonASCIISAN issues a certificate for key that crypto/x509
// refuses.
func newIssuedWithNonASCIISAN(t *testing.T, caCert *x509.Certificate, caKey, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:    big.NewInt(7),
		Subject:         pkix.Name{CommonName: "client"},
		NotBefore:       time.Now().Add(-time.Minute),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{nonASCIISAN(t)},
	}, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseCertificate(der); err == nil {
		t.Fatal("crypto/x509 accepts the certificate, the case does not test anything")
	}
	return der
}

// newCertRepFor returns a successful CertRep with certs, encrypted for
// recipient.
func newCertRepFor(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, recipient *x509.Certificate, encryption string, ber bool, certs ...[]byte) *scep.PKIMessage {
	t.Helper()
	degenerate, err := pkcs7.DegenerateCertificate(bytes.Join(certs, nil))
	if err != nil {
		t.Fatal(err)
	}
	if ber {
		degenerate = envelopetest.IndefiniteBER(t, degenerate)
	}
	envelope, err := encryptionAlgorithms[encryption](degenerate, []*x509.Certificate{recipient})
	if err != nil {
		t.Fatal(err)
	}
	return newCertRep(t, caCert, caKey, envelope)
}

// TestDecryptCertRepWithNonASCIISAN checks the issued certificate is returned
// even though crypto/x509 refuses its subjectAltName, after the CA in the chain
// and in a BER encoded degenerate SignedData too.
func TestDecryptCertRepWithNonASCIISAN(t *testing.T) {
	caCert, caKey := newTestCA(t)
	clientKey := newTestKey(t)
	signer, err := selfSign(clientKey, newTestCSR(t, clientKey))
	if err != nil {
		t.Fatal(err)
	}
	issuedDER := newIssuedWithNonASCIISAN(t, caCert, caKey, clientKey)

	for _, tc := range []struct {
		name       string
		encryption string
		certs      [][]byte
		ber        bool
	}{
		{name: "library", encryption: "aes256", certs: [][]byte{issuedDER}},
		{name: "envelope package", encryption: "aes192", certs: [][]byte{issuedDER}},
		{name: "CA first", encryption: "aes256", certs: [][]byte{caCert.Raw, issuedDER}},
		{name: "BER", encryption: "aes256", certs: [][]byte{caCert.Raw, issuedDER}, ber: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certRep := newCertRepFor(t, caCert, caKey, signer, tc.encryption, tc.ber, tc.certs...)
			got, err := decryptCertRep(certRep, signer, clientKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Raw, issuedDER) {
				t.Error("decryptCertRep returned a different certificate")
			}
		})
	}
}

// TestRenewalWithNonASCIISAN follows run from the stored certificate on: it
// is loaded, signs the RenewalReq and opens the CertRep encrypted for it.
func TestRenewalWithNonASCIISAN(t *testing.T) {
	caCert, caKey := newTestCA(t)
	clientKey := newTestKey(t)
	issuedDER := newIssuedWithNonASCIISAN(t, caCert, caKey, clientKey)

	certPath := filepath.Join(t.TempDir(), "client.pem")
	if err := os.WriteFile(certPath, pemCert(issuedDER), 0600); err != nil {
		t.Fatal(err)
	}
	cert, err := loadPEMCertFromFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert.Raw, issuedDER) || !bytes.Equal(cert.RawIssuer, caCert.RawSubject) || cert.SerialNumber.Cmp(big.NewInt(7)) != 0 {
		t.Error("the loaded certificate is not the issued one")
	}

	if _, err := newCSRRequest(newTestCSR(t, clientKey), &scep.PKIMessage{
		MessageType: scep.RenewalReq,
		Recipients:  []*x509.Certificate{caCert},
		SignerKey:   clientKey,
		SignerCert:  cert,
	}, scep.NopCertsSelector(), encryptionAlgorithms["aes256"], pkcs7.OIDDigestAlgorithmSHA256, log.NewNopLogger()); err != nil {
		t.Fatal(err)
	}

	renewedDER := newIssuedWithNonASCIISAN(t, caCert, caKey, clientKey)
	for _, encryption := range []string{"aes256", "aes192"} {
		t.Run(encryption, func(t *testing.T) {
			certRep := newCertRepFor(t, caCert, caKey, cert, encryption, false, renewedDER)
			got, err := decryptCertRep(certRep, cert, clientKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Raw, renewedDER) {
				t.Error("decryptCertRep returned a different certificate")
			}
		})
	}
}

func TestCertificateForKey(t *testing.T) {
	cert, key := envelopetest.NewRecipient(t)
	other, _ := envelopetest.NewRecipient(t)
	garbage := []byte{0x30, 0x03, 0x02, 0x01, 0x05}

	got, err := certificateForKey([][]byte{garbage, other.Raw, cert.Raw}, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Raw, cert.Raw) {
		t.Error("certificateForKey returned a different certificate")
	}

	_, err = certificateForKey([][]byte{garbage, other.Raw}, key)
	if err == nil {
		t.Fatal("expected an error when no certificate is for the key")
	}
	if !strings.Contains(err.Error(), "x509") {
		t.Errorf("error %q does not tell the unparsable certificate", err)
	}
}
