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
	"testing"
	"time"

	"github.com/smallstep/pkcs7"

	"github.com/micromdm/scep/v2/envelope/envelopetest"
)

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

func TestParseCSRMatchesCryptoX509(t *testing.T) {
	key := newTestKey(t)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "client", Organization: []string{"Proget"}, Country: []string{"PL"}},
		DNSNames: []string{"client.example.com"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	want, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}

	got, err := parseCSR(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Raw, want.Raw) ||
		!bytes.Equal(got.RawTBSCertificateRequest, want.RawTBSCertificateRequest) ||
		!bytes.Equal(got.RawSubjectPublicKeyInfo, want.RawSubjectPublicKeyInfo) ||
		!bytes.Equal(got.RawSubject, want.RawSubject) {
		t.Error("raw fields differ from crypto/x509")
	}
	if got.Subject.String() != want.Subject.String() {
		t.Errorf("Subject = %s, want %s", got.Subject, want.Subject)
	}
	if !got.PublicKey.(*rsa.PublicKey).Equal(want.PublicKey) {
		t.Error("PublicKey differs from crypto/x509")
	}
}

func TestParseCSRRejectsMalformedInput(t *testing.T) {
	for name, der := range map[string][]byte{
		"empty":         nil,
		"not a request": {0x02, 0x01, 0x05},
		"trailing data": append(mustCSR(t), 0x00),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCSR(der); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func mustCSR(t *testing.T) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "client"},
	}, newTestKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestDecryptCertRepWithNonASCIISAN checks the issued certificate is stored
// even though crypto/x509 refuses its subjectAltName, after the CA in the chain
// and in a BER encoded degenerate SignedData too.
func TestDecryptCertRepWithNonASCIISAN(t *testing.T) {
	caCert, caKey := newTestCA(t)
	clientKey := newTestKey(t)
	csr := newTestCSR(t, clientKey)
	signer, err := selfSign(clientKey, csr)
	if err != nil {
		t.Fatal(err)
	}
	issuedDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:    big.NewInt(7),
		Subject:         csr.Subject,
		NotBefore:       time.Now().Add(-time.Minute),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{nonASCIISAN(t)},
	}, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseCertificate(issuedDER); err == nil {
		t.Fatal("crypto/x509 accepts the certificate, the case does not test anything")
	}

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
			degenerate, err := pkcs7.DegenerateCertificate(bytes.Join(tc.certs, nil))
			if err != nil {
				t.Fatal(err)
			}
			if tc.ber {
				degenerate = envelopetest.IndefiniteBER(t, degenerate)
			}
			envelope, err := encryptionAlgorithms[tc.encryption](degenerate, []*x509.Certificate{signer})
			if err != nil {
				t.Fatal(err)
			}

			got, err := decryptCertRep(newCertRep(t, caCert, caKey, envelope), signer, clientKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, issuedDER) {
				t.Error("decryptCertRep returned a different certificate")
			}
		})
	}
}

func TestDegenerateCertificates(t *testing.T) {
	first, _ := envelopetest.NewRecipient(t)
	second, _ := envelopetest.NewRecipient(t)
	degenerate, err := pkcs7.DegenerateCertificate(append(append([]byte{}, first.Raw...), second.Raw...))
	if err != nil {
		t.Fatal(err)
	}

	for name, ber := range map[string][]byte{
		"DER": degenerate,
		"BER": envelopetest.IndefiniteBER(t, degenerate),
	} {
		t.Run(name, func(t *testing.T) {
			certs, err := degenerateCertificates(ber)
			if err != nil {
				t.Fatal(err)
			}
			if len(certs) != 2 || !bytes.Equal(certs[0], first.Raw) || !bytes.Equal(certs[1], second.Raw) {
				t.Errorf("got %d certificates, want both, in the order sent", len(certs))
			}
		})
	}

	t.Run("not signed data", func(t *testing.T) {
		enveloped, err := encryptionAlgorithms["aes128"](degenerate, []*x509.Certificate{first})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := degenerateCertificates(enveloped); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestCertificateForKeySkipsUnreadableCertificates(t *testing.T) {
	cert, key := envelopetest.NewRecipient(t)
	other, _ := envelopetest.NewRecipient(t)
	garbage := []byte{0x30, 0x03, 0x02, 0x01, 0x05}

	got, err := certificateForKey([][]byte{garbage, other.Raw, cert.Raw}, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, cert.Raw) {
		t.Error("certificateForKey returned a different certificate")
	}

	if _, err := certificateForKey([][]byte{garbage, other.Raw}, key); err == nil {
		t.Fatal("expected an error when no certificate is for the key")
	}
}
