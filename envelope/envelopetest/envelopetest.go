// Package envelopetest builds the CMS EnvelopedData variants SCEP servers and
// clients produce in the wild, for tests of code opening them.
package envelopetest

import (
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
)

var (
	oidMGF1       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidPSpecified = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 9}
)

// The ASN.1 structures are the ones of the envelope package, repeated so the
// helpers build envelopes independently of the code under test.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type envelopedData struct {
	Version              int
	RecipientInfos       []recipientInfo `asn1:"set"`
	EncryptedContentInfo asn1.RawValue
}

type recipientInfo struct {
	Version                int
	IssuerAndSerialNumber  asn1.RawValue
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type rsaOAEPParameters struct {
	HashFunc    pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
	MaskGenFunc pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	PSourceFunc pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:2"`
}

// NewRecipient returns a self-signed RSA certificate and its key, usable as an
// envelope recipient and as a CA.
func NewRecipient(t testing.TB) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
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

// WithOAEPKeyTransport rewraps the content key of the first recipient of a DER
// encoded, PKCS #1 v1.5 envelope with RSAES-OAEP, the key transport NDES uses
// when it answers in AES-192. params is the DER of the algorithm parameters,
// nil to leave them out.
func WithOAEPKeyTransport(t testing.TB, der []byte, key *rsa.PrivateKey, hash crypto.Hash, label []byte, params []byte) []byte {
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
	inner := MustMarshal(t, ed)
	return MustMarshal(t, contentInfo{
		ContentType: pkcs7.OIDEnvelopedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: inner, IsCompound: true},
	})
}

// DefaultOAEPParameters returns RSAES-OAEP-params with every field left at its
// default (SHA-1, MGF1 with SHA-1, empty label).
func DefaultOAEPParameters(t testing.TB) []byte {
	t.Helper()
	return MustMarshal(t, rsaOAEPParameters{})
}

// OAEPParameters returns RSAES-OAEP-params with every field spelled out.
func OAEPParameters(t testing.TB, digest, mgfDigest asn1.ObjectIdentifier, label []byte) []byte {
	t.Helper()
	return MustMarshal(t, rsaOAEPParameters{
		HashFunc: pkix.AlgorithmIdentifier{Algorithm: digest, Parameters: asn1.NullRawValue},
		MaskGenFunc: pkix.AlgorithmIdentifier{
			Algorithm:  oidMGF1,
			Parameters: asn1.RawValue{FullBytes: MustMarshal(t, pkix.AlgorithmIdentifier{Algorithm: mgfDigest, Parameters: asn1.NullRawValue})},
		},
		PSourceFunc: pkix.AlgorithmIdentifier{
			Algorithm:  oidPSpecified,
			Parameters: asn1.RawValue{FullBytes: MustMarshal(t, label)},
		},
	})
}

// IndefiniteBER re-encodes der the way streaming CMS encoders do: every
// constructed element gets an indefinite length, and the encrypted content
// ([0] IMPLICIT OCTET STRING) is split into a constructed string of chunks.
func IndefiniteBER(t testing.TB, der []byte) []byte {
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
			out = append(out, IndefiniteBER(t, v.Bytes)...)
			out = append(out, 0, 0)
		case v.Class == asn1.ClassContextSpecific && v.Tag == 0:
			out = append(out, v.FullBytes[0]|0x20, 0x80)
			for b := v.Bytes; len(b) > 0; {
				n := 16
				if n > len(b) {
					n = len(b)
				}
				out = append(out, MustMarshal(t, b[:n])...)
				b = b[n:]
			}
			out = append(out, 0, 0)
		default:
			out = append(out, v.FullBytes...)
		}
	}
	return out
}

// MustMarshal DER encodes v or fails the test.
func MustMarshal(t testing.TB, v interface{}) []byte {
	t.Helper()
	der, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
