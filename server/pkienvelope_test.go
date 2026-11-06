package scepserver_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
	"github.com/smallstep/scep/x509util"

	"github.com/micromdm/scep/v2/envelope"
	"github.com/micromdm/scep/v2/envelope/envelopetest"
	scepserver "github.com/micromdm/scep/v2/server"
)

var (
	oidSCEPmessageType   = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidSCEPsenderNonce   = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidSCEPtransactionID = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
)

// newPKCSReq signs enveloped into a PKCSReq pkiMessage the way SCEP clients do.
func newPKCSReq(t *testing.T, enveloped []byte, signer *x509.Certificate, key *rsa.PrivateKey) []byte {
	t.Helper()
	sd, err := pkcs7.NewSignedData(enveloped)
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	err = sd.AddSigner(signer, key, pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: []pkcs7.Attribute{
			{Type: oidSCEPtransactionID, Value: scep.TransactionID("tid")},
			{Type: oidSCEPmessageType, Value: scep.PKCSReq},
			{Type: oidSCEPsenderNonce, Value: scep.SenderNonce([]byte("0123456789abcdef"))},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestPKIOperationEnvelopes sends PKCSReqs encrypted the ways SCEP clients do,
// including the ones the pkcs7 library cannot open, and checks the CSR and the
// challenge reach the signer and a certificate comes back.
func TestPKIOperationEnvelopes(t *testing.T) {
	caCert, caKey := envelopetest.NewRecipient(t)
	const challenge = "secret"

	var signed *scep.CSRReqMessage
	signer := scepserver.CSRSignerContextFunc(func(_ context.Context, m *scep.CSRReqMessage) (*x509.Certificate, error) {
		signed = m
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(7),
			Subject:      m.CSR.Subject,
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(time.Hour),
		}, caCert, m.CSR.PublicKey, caKey)
		if err != nil {
			return nil, err
		}
		return x509.ParseCertificate(der)
	})
	svc, err := scepserver.NewService(caCert, caKey, scepserver.StaticChallengeMiddleware(challenge, signer))
	if err != nil {
		t.Fatal(err)
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	newCSR := func(t *testing.T, challenge string) *x509.CertificateRequest {
		der, err := x509util.CreateCertificateRequest(rand.Reader, &x509util.CertificateRequest{
			CertificateRequest: x509.CertificateRequest{Subject: pkix.Name{CommonName: "client"}},
			ChallengePassword:  challenge,
		}, clientKey)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			t.Fatal(err)
		}
		return csr
	}
	clientCert, err := selfSign(clientKey, newCSR(t, challenge))
	if err != nil {
		t.Fatal(err)
	}

	pkcs7Encrypt := func(alg int) func(t *testing.T, content []byte) []byte {
		return func(t *testing.T, content []byte) []byte {
			defer func(alg int) { pkcs7.ContentEncryptionAlgorithm = alg }(pkcs7.ContentEncryptionAlgorithm)
			pkcs7.ContentEncryptionAlgorithm = alg
			der, err := pkcs7.Encrypt(content, []*x509.Certificate{caCert})
			if err != nil {
				t.Fatal(err)
			}
			return der
		}
	}
	aesEncrypt := func(alg envelope.AESCBC, rewrap func(t *testing.T, der []byte) []byte) func(t *testing.T, content []byte) []byte {
		return func(t *testing.T, content []byte) []byte {
			der, err := alg.Encrypt(content, []*x509.Certificate{caCert})
			if err != nil {
				t.Fatal(err)
			}
			if rewrap != nil {
				der = rewrap(t, der)
			}
			return der
		}
	}
	oaep := func(hash crypto.Hash, params func(t *testing.T) []byte) func(t *testing.T, der []byte) []byte {
		return func(t *testing.T, der []byte) []byte {
			return envelopetest.WithOAEPKeyTransport(t, der, caKey, hash, nil, params(t))
		}
	}
	ber := func(t *testing.T, der []byte) []byte { return envelopetest.IndefiniteBER(t, der) }

	for _, tc := range []struct {
		name    string
		encrypt func(t *testing.T, content []byte) []byte
	}{
		{"DES", pkcs7Encrypt(pkcs7.EncryptionAlgorithmDESCBC)},
		{"AES-128", pkcs7Encrypt(pkcs7.EncryptionAlgorithmAES128CBC)},
		{"AES-256", pkcs7Encrypt(pkcs7.EncryptionAlgorithmAES256CBC)},
		{"AES-192", aesEncrypt(envelope.AES192CBC, nil)},
		{"AES-192 BER", aesEncrypt(envelope.AES192CBC, ber)},
		{"AES-192 OAEP", aesEncrypt(envelope.AES192CBC, oaep(crypto.SHA1, func(t *testing.T) []byte { return envelopetest.DefaultOAEPParameters(t) }))},
		{"AES-256 OAEP SHA-256", aesEncrypt(envelope.AES256CBC, oaep(crypto.SHA256, func(t *testing.T) []byte {
			return envelopetest.OAEPParameters(t, pkcs7.OIDDigestAlgorithmSHA256, pkcs7.OIDDigestAlgorithmSHA256, nil)
		}))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, c := range []struct {
				challenge string
				want      scep.PKIStatus
			}{{challenge, scep.SUCCESS}, {"wrong", scep.FAILURE}} {
				signed = nil
				csr := newCSR(t, c.challenge)
				req := newPKCSReq(t, tc.encrypt(t, csr.Raw), clientCert, clientKey)

				resp, err := svc.PKIOperation(context.Background(), req)
				if err != nil {
					t.Fatalf("challenge %q: PKIOperation: %v", c.challenge, err)
				}
				respMsg, err := scep.ParsePKIMessage(resp, scep.WithCACerts([]*x509.Certificate{caCert}))
				if err != nil {
					t.Fatal(err)
				}
				if respMsg.PKIStatus != c.want {
					t.Fatalf("challenge %q: pkiStatus = %s, want %s", c.challenge, respMsg.PKIStatus, c.want)
				}
				if c.want != scep.SUCCESS {
					continue
				}

				if signed == nil || string(signed.CSR.Raw) != string(csr.Raw) || signed.ChallengePassword != challenge {
					t.Fatal("the signer did not get the CSR and the challenge from the request")
				}
				if err := respMsg.DecryptPKIEnvelope(clientCert, clientKey); err != nil {
					t.Fatal(err)
				}
				if cn := respMsg.CertRepMessage.Certificate.Subject.CommonName; cn != "client" {
					t.Errorf("issued certificate CN = %q, want client", cn)
				}
			}
		})
	}
}
