package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/smallstep/pkcs7"
)

// withOAEPKeyTransport rewraps the content key of a PKCS #1 v1.5 envelope with
// RSAES-OAEP, the key transport NDES uses when it answers in AES-192.
func withOAEPKeyTransport(t *testing.T, der []byte, key *rsa.PrivateKey, hash crypto.Hash, label []byte, params []byte) []byte {
	t.Helper()
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		t.Fatal(err)
	}
	var ed envelopedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
		t.Fatal(err)
	}
	contentKey, err := rsa.DecryptPKCS1v15(nil, key, ed.RecipientInfos[0].EncryptedKey)
	if err != nil {
		t.Fatal(err)
	}
	encryptedKey, err := rsa.EncryptOAEP(hash.New(), rand.Reader, &key.PublicKey, contentKey, label)
	if err != nil {
		t.Fatal(err)
	}
	ed.RecipientInfos[0].EncryptedKey = encryptedKey
	ed.RecipientInfos[0].KeyEncryptionAlgorithm = pkix.AlgorithmIdentifier{
		Algorithm:  pkcs7.OIDEncryptionAlgorithmRSAESOAEP,
		Parameters: asn1.RawValue{FullBytes: params},
	}
	inner, err := asn1.Marshal(ed)
	if err != nil {
		t.Fatal(err)
	}
	out, err := asn1.Marshal(contentInfo{
		ContentType: pkcs7.OIDEnvelopedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: inner, IsCompound: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	der, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func explicitOAEPParameters(t *testing.T, digest asn1.ObjectIdentifier, mgfDigest asn1.ObjectIdentifier, label []byte) []byte {
	t.Helper()
	return mustMarshal(t, rsaOAEPParameters{
		HashFunc: pkix.AlgorithmIdentifier{Algorithm: digest, Parameters: asn1.NullRawValue},
		MaskGenFunc: pkix.AlgorithmIdentifier{
			Algorithm:  oidMGF1,
			Parameters: asn1.RawValue{FullBytes: mustMarshal(t, pkix.AlgorithmIdentifier{Algorithm: mgfDigest, Parameters: asn1.NullRawValue})},
		},
		PSourceFunc: pkix.AlgorithmIdentifier{
			Algorithm:  oidPSpecified,
			Parameters: asn1.RawValue{FullBytes: mustMarshal(t, label)},
		},
	})
}

func TestDecryptEnvelopeOAEP(t *testing.T) {
	caCert, caKey := newTestCA(t)
	content := []byte("issued certificate in a degenerate PKCS #7")

	for _, tc := range []struct {
		name   string
		hash   crypto.Hash
		label  []byte
		params func(t *testing.T) []byte
	}{
		{"default parameters (SHA-1)", crypto.SHA1, nil, func(t *testing.T) []byte { return mustMarshal(t, rsaOAEPParameters{}) }},
		{"absent parameters (SHA-1)", crypto.SHA1, nil, func(t *testing.T) []byte { return nil }},
		{"NULL parameters (SHA-1)", crypto.SHA1, nil, func(t *testing.T) []byte { return asn1.NullBytes }},
		{"SHA-256 with label", crypto.SHA256, []byte("label"), func(t *testing.T) []byte {
			return explicitOAEPParameters(t, pkcs7.OIDDigestAlgorithmSHA256, pkcs7.OIDDigestAlgorithmSHA256, []byte("label"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der, err := aesCBCAlgorithms[1].encrypt(content, []*x509.Certificate{caCert})
			if err != nil {
				t.Fatal(err)
			}
			der = withOAEPKeyTransport(t, der, caKey, tc.hash, tc.label, tc.params(t))

			got, err := decryptEnvelope(der, caCert, caKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, content) {
				t.Fatalf("decryptEnvelope = %q, want %q", got, content)
			}
		})
	}
}

func TestDecryptEnvelopeOAEPRejectsMismatchedMGF1Hash(t *testing.T) {
	caCert, caKey := newTestCA(t)
	der, err := aesCBCAlgorithms[1].encrypt([]byte("content"), []*x509.Certificate{caCert})
	if err != nil {
		t.Fatal(err)
	}
	params := explicitOAEPParameters(t, pkcs7.OIDDigestAlgorithmSHA256, pkcs7.OIDDigestAlgorithmSHA1, nil)
	der = withOAEPKeyTransport(t, der, caKey, crypto.SHA256, nil, params)

	if _, err := decryptEnvelope(der, caCert, caKey); err == nil {
		t.Fatal("expected an error for an MGF1 hash different from the OAEP hash")
	}
}

// TestDecryptEnvelopeOAEPOpenSSL opens AES-192 envelopes whose content key
// openssl wrapped with RSAES-OAEP, as a SCEP server answering in AES-192 does.
func TestDecryptEnvelopeOAEPOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	caCert, caKey := newTestCA(t)
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

			got, err := decryptEnvelope(der, caCert, caKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, content) {
				t.Fatalf("decryptEnvelope = %q, want %q", got, content)
			}
		})
	}
}

// indefiniteBER re-encodes der the way streaming CMS encoders do: every
// constructed element gets an indefinite length, and the encrypted content
// ([0] IMPLICIT OCTET STRING) is split into a constructed string of chunks.
func indefiniteBER(t *testing.T, der []byte) []byte {
	t.Helper()
	var out []byte
	for rest := der; len(rest) > 0; {
		var v asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &v); err != nil {
			t.Fatal(err)
		}
		if v.FullBytes[0]&0x1f == 0x1f {
			t.Fatal("high tag numbers are not supported")
		}
		switch {
		case v.IsCompound:
			out = append(out, v.FullBytes[0], 0x80)
			out = append(out, indefiniteBER(t, v.Bytes)...)
			out = append(out, 0, 0)
		case v.Class == asn1.ClassContextSpecific && v.Tag == 0:
			out = append(out, v.FullBytes[0]|0x20, 0x80)
			for b := v.Bytes; len(b) > 0; {
				n := 16
				if n > len(b) {
					n = len(b)
				}
				out = append(out, mustMarshal(t, b[:n])...)
				b = b[n:]
			}
			out = append(out, 0, 0)
		default:
			out = append(out, v.FullBytes...)
		}
	}
	return out
}

func TestDecryptEnvelopeBER(t *testing.T) {
	caCert, caKey := newTestCA(t)
	content := []byte("long enough to span several encrypted content chunks")

	der, err := aesCBCAlgorithms[1].encrypt(content, []*x509.Certificate{caCert})
	if err != nil {
		t.Fatal(err)
	}
	ber := indefiniteBER(t, der)
	if _, err := asn1.Unmarshal(ber, new(asn1.RawValue)); err == nil {
		t.Fatal("encoding/asn1 accepts the test input, it is not BER only")
	}

	got, err := decryptEnvelope(ber, caCert, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("decryptEnvelope = %q, want %q", got, content)
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
