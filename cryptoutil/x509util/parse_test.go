package x509util

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"reflect"
	"testing"
	"time"
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

func newKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

var testSubject = pkix.Name{CommonName: "client", Organization: []string{"Proget"}, Country: []string{"PL"}}

func newCSR(t *testing.T, key *rsa.PrivateKey, extensions ...pkix.Extension) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:         testSubject,
		DNSNames:        []string{"client.example.com"},
		ExtraExtensions: extensions,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func newCertificate(t *testing.T, key *rsa.PrivateKey, extensions ...pkix.Extension) []byte {
	t.Helper()
	caKey := newKey(t)
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test CA"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:    big.NewInt(7),
		Subject:         testSubject,
		NotBefore:       time.Now().Add(-time.Minute).Truncate(time.Second),
		NotAfter:        time.Now().Add(time.Hour).Truncate(time.Second),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: extensions,
	}, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseCertificateRequestWithNonASCIISAN(t *testing.T) {
	key := newKey(t)
	der := newCSR(t, key, nonASCIISAN(t))
	if _, err := x509.ParseCertificateRequest(der); err == nil {
		t.Fatal("crypto/x509 accepts the request, the case does not test anything")
	}

	csr, err := ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(csr.Raw, der) {
		t.Error("Raw is not the request")
	}
	if pub, ok := csr.PublicKey.(*rsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		t.Errorf("PublicKey = %v, want the key of the request", csr.PublicKey)
	}
	if got, want := csr.Subject.String(), testSubject.String(); got != want {
		t.Errorf("Subject = %s, want %s", got, want)
	}
}

// TestParseRawCertificateRequestMatchesCryptoX509 checks the fields the
// fallback sets are the ones crypto/x509 sets.
func TestParseRawCertificateRequestMatchesCryptoX509(t *testing.T) {
	der := newCSR(t, newKey(t))
	want, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseRawCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	for name, eq := range map[string]bool{
		"Raw":                      bytes.Equal(got.Raw, want.Raw),
		"RawTBSCertificateRequest": bytes.Equal(got.RawTBSCertificateRequest, want.RawTBSCertificateRequest),
		"RawSubjectPublicKeyInfo":  bytes.Equal(got.RawSubjectPublicKeyInfo, want.RawSubjectPublicKeyInfo),
		"RawSubject":               bytes.Equal(got.RawSubject, want.RawSubject),
		"Version":                  got.Version == want.Version,
		"Signature":                bytes.Equal(got.Signature, want.Signature),
		"Subject":                  got.Subject.String() == want.Subject.String(),
		"PublicKey":                got.PublicKey.(*rsa.PublicKey).Equal(want.PublicKey),
	} {
		if !eq {
			t.Errorf("%s differs from crypto/x509", name)
		}
	}
}

func TestParseCertificateRequestRejectsMalformedInput(t *testing.T) {
	der := newCSR(t, newKey(t), nonASCIISAN(t))
	mutate := func(f func(*certificateRequest)) []byte {
		var req certificateRequest
		if _, err := asn1.Unmarshal(der, &req); err != nil {
			t.Fatal(err)
		}
		req.Raw, req.TBSCSR.Raw = nil, nil
		f(&req)
		out, err := asn1.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	notAName := asn1.RawValue{FullBytes: []byte{0x02, 0x01, 0x05}}

	if _, err := ParseCertificateRequest(mutate(func(*certificateRequest) {})); err != nil {
		t.Fatalf("the unchanged request is refused: %v", err)
	}
	var info struct{ Info asn1.RawValue }
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		t.Fatal(err)
	}
	for name, der := range map[string][]byte{
		"empty":              nil,
		"not a request":      {0x02, 0x01, 0x05},
		"trailing data":      append(append([]byte{}, der...), 0x00),
		"info only":          mustMarshal(t, info),
		"subject not a name": mutate(func(req *certificateRequest) { req.TBSCSR.Subject = notAName }),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCertificateRequest(der); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestParseCertificateWithNonASCIISAN(t *testing.T) {
	key := newKey(t)
	der := newCertificate(t, key, nonASCIISAN(t))
	if _, err := x509.ParseCertificate(der); err == nil {
		t.Fatal("crypto/x509 accepts the certificate, the case does not test anything")
	}

	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert.Raw, der) {
		t.Error("Raw is not the certificate")
	}
	if pub, ok := cert.PublicKey.(*rsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		t.Errorf("PublicKey = %v, want the key of the certificate", cert.PublicKey)
	}
	if cert.SerialNumber.Cmp(big.NewInt(7)) != 0 {
		t.Errorf("SerialNumber = %s, want 7", cert.SerialNumber)
	}
	if got, want := cert.Issuer.CommonName, "test CA"; got != want {
		t.Errorf("Issuer.CommonName = %q, want %q", got, want)
	}
}

// TestParseRawCertificateMatchesCryptoX509 checks the fields the fallback sets
// are the ones crypto/x509 sets.
func TestParseRawCertificateMatchesCryptoX509(t *testing.T) {
	der := newCertificate(t, newKey(t))
	want, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseRawCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	for name, eq := range map[string]bool{
		"Raw":                     bytes.Equal(got.Raw, want.Raw),
		"RawTBSCertificate":       bytes.Equal(got.RawTBSCertificate, want.RawTBSCertificate),
		"RawSubjectPublicKeyInfo": bytes.Equal(got.RawSubjectPublicKeyInfo, want.RawSubjectPublicKeyInfo),
		"RawSubject":              bytes.Equal(got.RawSubject, want.RawSubject),
		"RawIssuer":               bytes.Equal(got.RawIssuer, want.RawIssuer),
		"Version":                 got.Version == want.Version,
		"SerialNumber":            got.SerialNumber.Cmp(want.SerialNumber) == 0,
		"Signature":               bytes.Equal(got.Signature, want.Signature),
		"Issuer":                  got.Issuer.String() == want.Issuer.String(),
		"Subject":                 got.Subject.String() == want.Subject.String(),
		"NotBefore":               got.NotBefore.Equal(want.NotBefore),
		"NotAfter":                got.NotAfter.Equal(want.NotAfter),
		"PublicKey":               got.PublicKey.(*rsa.PublicKey).Equal(want.PublicKey),
		"Extensions":              reflect.DeepEqual(got.Extensions, want.Extensions),
	} {
		if !eq {
			t.Errorf("%s differs from crypto/x509", name)
		}
	}
}

func TestParseCertificateRejectsMalformedInput(t *testing.T) {
	der := newCertificate(t, newKey(t), nonASCIISAN(t))
	mutate := func(f func(*certificate)) []byte {
		var c certificate
		if _, err := asn1.Unmarshal(der, &c); err != nil {
			t.Fatal(err)
		}
		c.Raw, c.TBSCertificate.Raw = nil, nil
		f(&c)
		out, err := asn1.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	notAName := asn1.RawValue{FullBytes: []byte{0x02, 0x01, 0x05}}

	if _, err := ParseCertificate(mutate(func(*certificate) {})); err != nil {
		t.Fatalf("the unchanged certificate is refused: %v", err)
	}
	var tbs struct{ TBS asn1.RawValue }
	if _, err := asn1.Unmarshal(der, &tbs); err != nil {
		t.Fatal(err)
	}
	for name, der := range map[string][]byte{
		"empty":              nil,
		"not a certificate":  {0x02, 0x01, 0x05},
		"trailing data":      append(append([]byte{}, der...), 0x00),
		"no signature":       mustMarshal(t, tbs),
		"subject not a name": mutate(func(c *certificate) { c.TBSCertificate.Subject = notAName }),
		"issuer not a name":  mutate(func(c *certificate) { c.TBSCertificate.Issuer = notAName }),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCertificate(der); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	der, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
