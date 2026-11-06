package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
)

func newTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newTestCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key := newTestKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func newTestCSR(t *testing.T, key *rsa.PrivateKey) *x509.CertificateRequest {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "client"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func TestAESEnvelopeRoundTrip(t *testing.T) {
	caCert, caKey := newTestCA(t)
	content := []byte("a CSR, or anything else that needs padding")

	for _, alg := range aesCBCAlgorithms {
		t.Run(alg.oid.String(), func(t *testing.T) {
			der, err := alg.encrypt(content, []*x509.Certificate{caCert})
			if err != nil {
				t.Fatal(err)
			}

			got, err := decryptEnvelope(der, caCert, caKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, content) {
				t.Fatalf("decryptEnvelope = %q, want %q", got, content)
			}

			// cross-check against the pkcs7 library where it supports the cipher
			if alg.oid.Equal(oidAES192CBC) {
				return
			}
			p7, err := pkcs7.Parse(der)
			if err != nil {
				t.Fatal(err)
			}
			got, err = p7.Decrypt(caCert, caKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, content) {
				t.Fatalf("pkcs7 Decrypt = %q, want %q", got, content)
			}
		})
	}
}

// TestAESEnvelopeOpenSSL checks interoperability with an independent CMS
// implementation, which matters most for AES-192.
func TestAESEnvelopeOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	caCert, caKey := newTestCA(t)
	content := []byte("decrypted by openssl")

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")
	writePEM(t, certPath, "CERTIFICATE", caCert.Raw)
	writePEM(t, keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caKey))

	for _, alg := range aesCBCAlgorithms {
		t.Run(alg.oid.String(), func(t *testing.T) {
			der, err := alg.encrypt(content, []*x509.Certificate{caCert})
			if err != nil {
				t.Fatal(err)
			}
			in := filepath.Join(dir, "envelope.der")
			if err := os.WriteFile(in, der, 0600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("openssl", "cms", "-decrypt", "-inform", "DER", "-in", in,
				"-recip", certPath, "-inkey", keyPath).CombinedOutput()
			if err != nil {
				t.Fatalf("openssl cms -decrypt: %v\n%s", err, out)
			}
			if !bytes.Equal(out, content) {
				t.Fatalf("openssl decrypted %q, want %q", out, content)
			}
		})
	}
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestNewCSRRequest(t *testing.T) {
	caCert, caKey := newTestCA(t)
	clientKey := newTestKey(t)
	csr := newTestCSR(t, clientKey)
	signer, err := selfSign(clientKey, csr)
	if err != nil {
		t.Fatal(err)
	}

	for encName, encrypt := range encryptionAlgorithms {
		for digestName, digest := range signatureAlgorithms {
			t.Run(encName+"/"+digestName, func(t *testing.T) {
				raw, err := newCSRRequest(csr, &scep.PKIMessage{
					MessageType: scep.PKCSReq,
					Recipients:  []*x509.Certificate{caCert},
					SignerKey:   clientKey,
					SignerCert:  signer,
				}, scep.NopCertsSelector(), encrypt, digest, log.NewNopLogger())
				if err != nil {
					t.Fatal(err)
				}

				// what the SCEP server does: verify the signature, then decrypt
				msg, err := scep.ParsePKIMessage(raw)
				if err != nil {
					t.Fatal(err)
				}
				if msg.MessageType != scep.PKCSReq {
					t.Errorf("message type = %s, want %s", msg.MessageType, scep.PKCSReq)
				}

				p7, err := pkcs7.Parse(raw)
				if err != nil {
					t.Fatal(err)
				}
				if got := p7.Signers[0].DigestAlgorithm.Algorithm; !got.Equal(digest) {
					t.Errorf("digest algorithm = %s, want %s", got, digest)
				}

				ed, err := parseEnvelope(p7.Content)
				if err != nil {
					t.Fatal(err)
				}
				if got := ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm; !got.Equal(encryptionOIDs[encName]) {
					t.Errorf("content encryption = %s, want %s", got, encryptionOIDs[encName])
				}

				var envelope []byte
				if encName == "aes192" {
					envelope, err = decryptEnvelope(p7.Content, caCert, caKey)
				} else {
					envelope, err = p7Decrypt(p7.Content, caCert, caKey)
				}
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(envelope, csr.Raw) {
					t.Error("decrypted envelope is not the CSR")
				}
			})
		}
	}
}

var encryptionOIDs = map[string]asn1.ObjectIdentifier{
	"des":    pkcs7.OIDEncryptionAlgorithmDESCBC,
	"aes128": oidAES128CBC,
	"aes192": oidAES192CBC,
	"aes256": oidAES256CBC,
}

func p7Decrypt(der []byte, cert *x509.Certificate, key *rsa.PrivateKey) ([]byte, error) {
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, err
	}
	return p7.Decrypt(cert, key)
}

func TestNewCSRRequestRejectsUnselectedRecipients(t *testing.T) {
	caCert, _ := newTestCA(t)
	clientKey := newTestKey(t)
	csr := newTestCSR(t, clientKey)
	signer, err := selfSign(clientKey, csr)
	if err != nil {
		t.Fatal(err)
	}

	_, err = newCSRRequest(csr, &scep.PKIMessage{
		MessageType: scep.PKCSReq,
		Recipients:  []*x509.Certificate{caCert},
		SignerKey:   clientKey,
		SignerCert:  signer,
	}, scep.FingerprintCertsSelector(fingerprintHashType, make([]byte, 32)), aesCBCAlgorithms[0].encrypt, pkcs7.OIDDigestAlgorithmSHA256, log.NewNopLogger())
	if err == nil {
		t.Fatal("expected an error when the selector drops every recipient")
	}
}

// newCertRep builds a successful CertRep carrying envelope, signed by the CA
// the way a SCEP server would, and parses it as the client does.
func newCertRep(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, envelope []byte) *scep.PKIMessage {
	t.Helper()
	sd, err := pkcs7.NewSignedData(envelope)
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	nonce := []byte("0123456789abcdef")
	err = sd.AddSigner(caCert, caKey, pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: []pkcs7.Attribute{
			{Type: oidSCEPtransactionID, Value: scep.TransactionID("tid")},
			{Type: oidSCEPmessageType, Value: scep.CertRep},
			{Type: asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}, Value: scep.SUCCESS},
			{Type: asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}, Value: scep.RecipientNonce(nonce)},
			{Type: oidSCEPsenderNonce, Value: scep.SenderNonce(nonce)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	respMsg, err := scep.ParsePKIMessage(raw, scep.WithCACerts([]*x509.Certificate{caCert}))
	if err != nil {
		t.Fatal(err)
	}
	return respMsg
}

// TestDecryptCertRep checks the client gets the issued certificate out of
// CertReps encrypted the ways SCEP servers do, whether the pkcs7 library or
// decryptEnvelope has to open them.
func TestDecryptCertRep(t *testing.T) {
	caCert, caKey := newTestCA(t)
	clientKey := newTestKey(t)
	csr := newTestCSR(t, clientKey)
	signer, err := selfSign(clientKey, csr)
	if err != nil {
		t.Fatal(err)
	}

	issuedDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	degenerate, err := pkcs7.DegenerateCertificate(issuedDER)
	if err != nil {
		t.Fatal(err)
	}

	oaep := func(hash crypto.Hash, label []byte, params func(t *testing.T) []byte) func(t *testing.T, der []byte) []byte {
		return func(t *testing.T, der []byte) []byte {
			return withOAEPKeyTransport(t, der, clientKey, hash, label, params(t))
		}
	}
	for _, tc := range []struct {
		name       string
		encryption string
		rewrap     func(t *testing.T, der []byte) []byte
		// the pkcs7 library alone cannot open the envelope
		libraryFails bool
	}{
		{name: "DES", encryption: "des"},
		{name: "AES-128", encryption: "aes128"},
		{name: "AES-256", encryption: "aes256"},
		{name: "AES-192", encryption: "aes192", libraryFails: true},
		{name: "AES-192 BER", encryption: "aes192", libraryFails: true, rewrap: func(t *testing.T, der []byte) []byte {
			return indefiniteBER(t, der)
		}},
		{name: "AES-256 OAEP default parameters", encryption: "aes256", rewrap: oaep(crypto.SHA1, nil, func(t *testing.T) []byte {
			return mustMarshal(t, rsaOAEPParameters{})
		})},
		{name: "AES-128 OAEP absent parameters", encryption: "aes128", libraryFails: true, rewrap: oaep(crypto.SHA1, nil, func(t *testing.T) []byte {
			return nil
		})},
		{name: "AES-256 OAEP NULL parameters", encryption: "aes256", libraryFails: true, rewrap: oaep(crypto.SHA1, nil, func(t *testing.T) []byte {
			return asn1.NullBytes
		})},
		{name: "AES-256 OAEP SHA-256 with label", encryption: "aes256", libraryFails: true, rewrap: oaep(crypto.SHA256, []byte("label"), func(t *testing.T) []byte {
			return explicitOAEPParameters(t, pkcs7.OIDDigestAlgorithmSHA256, pkcs7.OIDDigestAlgorithmSHA256, []byte("label"))
		})},
		{name: "AES-192 OAEP SHA-256", encryption: "aes192", libraryFails: true, rewrap: oaep(crypto.SHA256, nil, func(t *testing.T) []byte {
			return explicitOAEPParameters(t, pkcs7.OIDDigestAlgorithmSHA256, pkcs7.OIDDigestAlgorithmSHA256, nil)
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			envelope, err := encryptionAlgorithms[tc.encryption](degenerate, []*x509.Certificate{signer})
			if err != nil {
				t.Fatal(err)
			}
			if tc.rewrap != nil {
				envelope = tc.rewrap(t, envelope)
			}

			// make sure the case exercises what it claims to
			err = newCertRep(t, caCert, caKey, envelope).DecryptPKIEnvelope(signer, clientKey)
			if tc.libraryFails && err == nil {
				t.Fatal("pkcs7 library opened the envelope, the case does not need decryptEnvelope")
			} else if !tc.libraryFails && err != nil {
				t.Fatalf("pkcs7 library: %v", err)
			}

			got, err := decryptCertRep(newCertRep(t, caCert, caKey, envelope), signer, clientKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Raw, issuedDER) {
				t.Error("decryptCertRep returned a different certificate")
			}
		})
	}
}

func TestDecryptCertRepReportsLibraryAndParseErrors(t *testing.T) {
	caCert, caKey := newTestCA(t)
	clientKey := newTestKey(t)
	signer, err := selfSign(clientKey, newTestCSR(t, clientKey))
	if err != nil {
		t.Fatal(err)
	}
	// signed data instead of enveloped data: neither parser accepts it
	notEnveloped, err := pkcs7.DegenerateCertificate(caCert.Raw)
	if err != nil {
		t.Fatal(err)
	}

	_, err = decryptCertRep(newCertRep(t, caCert, caKey, notEnveloped), signer, clientKey)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, pkcs7.ErrNotEncryptedContent) || !strings.Contains(err.Error(), "unexpected content type") {
		t.Errorf("error = %q, want both the library and the envelope parser error", err)
	}
}
