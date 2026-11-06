package envelope

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/smallstep/pkcs7"

	"github.com/micromdm/scep/v2/envelope/envelopetest"
)

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestAESEnvelopeRoundTrip(t *testing.T) {
	caCert, caKey := envelopetest.NewRecipient(t)
	content := []byte("a CSR, or anything else that needs padding")

	for _, alg := range aesCBCAlgorithms {
		t.Run(alg.oid.String(), func(t *testing.T) {
			der, err := alg.Encrypt(content, []*x509.Certificate{caCert})
			if err != nil {
				t.Fatal(err)
			}

			got, err := Decrypt(der, caCert, caKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, content) {
				t.Fatalf("Decrypt = %q, want %q", got, content)
			}

			// cross-check against the pkcs7 library where it supports the cipher
			if alg.oid.Equal(OIDAES192CBC) {
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
	caCert, caKey := envelopetest.NewRecipient(t)
	content := []byte("decrypted by openssl")

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")
	writePEM(t, certPath, "CERTIFICATE", caCert.Raw)
	writePEM(t, keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caKey))

	for _, alg := range aesCBCAlgorithms {
		t.Run(alg.oid.String(), func(t *testing.T) {
			der, err := alg.Encrypt(content, []*x509.Certificate{caCert})
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

func TestDecryptOAEP(t *testing.T) {
	caCert, caKey := envelopetest.NewRecipient(t)
	content := []byte("issued certificate in a degenerate PKCS #7")

	for _, tc := range []struct {
		name   string
		hash   crypto.Hash
		label  []byte
		params func(t *testing.T) []byte
	}{
		{"default parameters (SHA-1)", crypto.SHA1, nil, func(t *testing.T) []byte { return envelopetest.DefaultOAEPParameters(t) }},
		{"absent parameters (SHA-1)", crypto.SHA1, nil, func(t *testing.T) []byte { return nil }},
		{"NULL parameters (SHA-1)", crypto.SHA1, nil, func(t *testing.T) []byte { return asn1.NullBytes }},
		{"SHA-256 with label", crypto.SHA256, []byte("label"), func(t *testing.T) []byte {
			return envelopetest.OAEPParameters(t, pkcs7.OIDDigestAlgorithmSHA256, pkcs7.OIDDigestAlgorithmSHA256, []byte("label"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der, err := AES192CBC.Encrypt(content, []*x509.Certificate{caCert})
			if err != nil {
				t.Fatal(err)
			}
			der = envelopetest.WithOAEPKeyTransport(t, der, caKey, tc.hash, tc.label, tc.params(t))

			got, err := Decrypt(der, caCert, caKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, content) {
				t.Fatalf("Decrypt = %q, want %q", got, content)
			}
		})
	}
}

func TestDecryptOAEPRejectsMismatchedMGF1Hash(t *testing.T) {
	caCert, caKey := envelopetest.NewRecipient(t)
	der, err := AES192CBC.Encrypt([]byte("content"), []*x509.Certificate{caCert})
	if err != nil {
		t.Fatal(err)
	}
	params := envelopetest.OAEPParameters(t, pkcs7.OIDDigestAlgorithmSHA256, pkcs7.OIDDigestAlgorithmSHA1, nil)
	der = envelopetest.WithOAEPKeyTransport(t, der, caKey, crypto.SHA256, nil, params)

	if _, err := Decrypt(der, caCert, caKey); err == nil {
		t.Fatal("expected an error for an MGF1 hash different from the OAEP hash")
	}
}

// TestDecryptOAEPOpenSSL opens AES-192 envelopes whose content key openssl
// wrapped with RSAES-OAEP, as a SCEP server answering in AES-192 does.
func TestDecryptOAEPOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	caCert, caKey := envelopetest.NewRecipient(t)
	content := []byte("encrypted by openssl")

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	inPath := filepath.Join(dir, "content")
	writePEM(t, certPath, "CERTIFICATE", caCert.Raw)
	if err := os.WriteFile(inPath, content, 0600); err != nil {
		t.Fatal(err)
	}

	for name, keyopts := range map[string][]string{
		"SHA-1":   {"-keyopt", "rsa_padding_mode:oaep"},
		"SHA-256": {"-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256", "-keyopt", "rsa_mgf1_md:sha256"},
		// -stream writes BER with indefinite lengths
		"SHA-1 streamed": {"-stream", "-keyopt", "rsa_padding_mode:oaep"},
	} {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"cms", "-encrypt", "-binary", "-aes192", "-in", inPath, "-outform", "DER", "-recip", certPath}, keyopts...)
			der, err := exec.Command("openssl", args...).Output()
			if err != nil {
				t.Fatalf("openssl cms -encrypt: %v", err)
			}

			got, err := Decrypt(der, caCert, caKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, content) {
				t.Fatalf("Decrypt = %q, want %q", got, content)
			}
		})
	}
}

func TestDecryptBER(t *testing.T) {
	caCert, caKey := envelopetest.NewRecipient(t)
	content := []byte("long enough to span several encrypted content chunks")

	der, err := AES192CBC.Encrypt(content, []*x509.Certificate{caCert})
	if err != nil {
		t.Fatal(err)
	}
	ber := envelopetest.IndefiniteBER(t, der)
	if _, err := asn1.Unmarshal(ber, new(asn1.RawValue)); err == nil {
		t.Fatal("encoding/asn1 accepts the test input, it is not BER only")
	}

	got, err := Decrypt(ber, caCert, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("Decrypt = %q, want %q", got, content)
	}
}

func TestUnsupportedByPKCS7(t *testing.T) {
	caCert, caKey := envelopetest.NewRecipient(t)
	otherCert, _ := envelopetest.NewRecipient(t)
	otherCert.SerialNumber.SetInt64(43)
	content := []byte("content")

	encrypt := func(t *testing.T, alg AESCBC) []byte {
		der, err := alg.Encrypt(content, []*x509.Certificate{caCert})
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	des := func(t *testing.T) []byte {
		defer func(alg int) { pkcs7.ContentEncryptionAlgorithm = alg }(pkcs7.ContentEncryptionAlgorithm)
		pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmDESCBC
		der, err := pkcs7.Encrypt(content, []*x509.Certificate{caCert})
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	oaep := func(t *testing.T, der []byte) []byte {
		return envelopetest.WithOAEPKeyTransport(t, der, caKey, crypto.SHA1, nil, nil)
	}

	for _, tc := range []struct {
		name     string
		envelope func(t *testing.T) []byte
		cert     *x509.Certificate
		want     bool
	}{
		{"DES", des, caCert, false},
		{"AES-128", func(t *testing.T) []byte { return encrypt(t, AES128CBC) }, caCert, false},
		{"AES-256", func(t *testing.T) []byte { return encrypt(t, AES256CBC) }, caCert, false},
		{"AES-192", func(t *testing.T) []byte { return encrypt(t, AES192CBC) }, caCert, true},
		{"AES-192 for another recipient", func(t *testing.T) []byte { return encrypt(t, AES192CBC) }, otherCert, true},
		{"AES-256 OAEP", func(t *testing.T) []byte { return oaep(t, encrypt(t, AES256CBC)) }, caCert, true},
		{"AES-256 OAEP for another recipient", func(t *testing.T) []byte { return oaep(t, encrypt(t, AES256CBC)) }, otherCert, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ed, err := Parse(tc.envelope(t))
			if err != nil {
				t.Fatal(err)
			}
			if got := ed.UnsupportedByPKCS7(tc.cert); got != tc.want {
				t.Errorf("UnsupportedByPKCS7 = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBERToDER(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ber     []byte
		want    []byte
		wantErr bool
	}{
		{name: "DER is kept", ber: []byte{0x30, 0x03, 0x02, 0x01, 0x05}, want: []byte{0x30, 0x03, 0x02, 0x01, 0x05}},
		{name: "indefinite length", ber: []byte{0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00}, want: []byte{0x30, 0x03, 0x02, 0x01, 0x05}},
		{name: "nested indefinite lengths", ber: []byte{0x30, 0x80, 0xa0, 0x80, 0x04, 0x01, 0xff, 0x00, 0x00, 0x00, 0x00}, want: []byte{0x30, 0x05, 0xa0, 0x03, 0x04, 0x01, 0xff}},
		{name: "non-minimal length", ber: []byte{0x04, 0x82, 0x00, 0x01, 0xff}, want: []byte{0x04, 0x01, 0xff}},
		{name: "high tag number", ber: []byte{0xbf, 0x81, 0x00, 0x80, 0x05, 0x00, 0x00, 0x00}, want: []byte{0xbf, 0x81, 0x00, 0x02, 0x05, 0x00}},
		{name: "empty", ber: nil, wantErr: true},
		{name: "missing end of contents", ber: []byte{0x30, 0x80, 0x02, 0x01, 0x05}, wantErr: true},
		{name: "indefinite primitive", ber: []byte{0x04, 0x80, 0x00, 0x00}, wantErr: true},
		{name: "length past the end", ber: []byte{0x04, 0x05, 0xff}, wantErr: true},
		{name: "huge length", ber: []byte{0x04, 0x84, 0xff, 0xff, 0xff, 0xff}, wantErr: true},
		{name: "trailing data", ber: []byte{0x05, 0x00, 0x05, 0x00}, wantErr: true},
		{name: "too deep", ber: bytes.Repeat([]byte{0x30, 0x80}, maxBERDepth+2), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := berToDER(tc.ber)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("berToDER = %x, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("berToDER = %x, want %x", got, tc.want)
			}
		})
	}
}
