package envelope

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"github.com/smallstep/pkcs7"

	"github.com/micromdm/scep/v2/envelope/envelopetest"
)

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
			certs, err := DegenerateCertificates(ber)
			if err != nil {
				t.Fatal(err)
			}
			if len(certs) != 2 || !bytes.Equal(certs[0], first.Raw) || !bytes.Equal(certs[1], second.Raw) {
				t.Errorf("got %d certificates, want both, in the order sent", len(certs))
			}
		})
	}

	var ci contentInfo
	if _, err := asn1.Unmarshal(degenerate, &ci); err != nil {
		t.Fatal(err)
	}
	withSignedData := func(sd []byte) []byte {
		return envelopetest.MustMarshal(t, struct {
			ContentType asn1.ObjectIdentifier
			Content     asn1.RawValue
		}{
			ContentType: pkcs7.OIDSignedData,
			Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sd},
		})
	}
	if _, err := DegenerateCertificates(withSignedData(ci.Content.Bytes)); err != nil {
		t.Fatalf("the rebuilt content info is refused: %v", err)
	}
	var truncated struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		EncapContentInfo asn1.RawValue
		Certificates     asn1.RawValue
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &truncated); err != nil {
		t.Fatal(err)
	}

	enveloped, err := AES192CBC.Encrypt(degenerate, []*x509.Certificate{first})
	if err != nil {
		t.Fatal(err)
	}
	for name, ber := range map[string][]byte{
		"not signed data":                 enveloped,
		"trailing data after signed data": withSignedData(append(append([]byte{}, ci.Content.Bytes...), 0x05, 0x00)),
		"no signer infos":                 withSignedData(envelopetest.MustMarshal(t, truncated)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DegenerateCertificates(ber); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
