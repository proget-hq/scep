package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/micromdm/scep/v2/envelope"
)

// crypto/x509 rejects requests and certificates whose subjectAltName holds an
// rfc822Name, dNSName or URI that is not ASCII, which OpenSSL writes as given.
// sscep sends such requests and stores such certificates, and the SCEP server,
// not the client, decides what it issues. scepclient needs only the DER, the
// public key and, of the request, the subject, so it reads those itself.

// certificationRequest is the start of a PKCS #10 CertificationRequest
// (RFC 2986). encoding/asn1 ignores the elements after the last field.
type certificationRequest struct {
	Info struct {
		Raw       asn1.RawContent
		Version   int
		Subject   asn1.RawValue
		PublicKey asn1.RawValue
	}
}

// parseCSR reads a DER certificate request without validating its attributes
// and extensions.
func parseCSR(der []byte) (*x509.CertificateRequest, error) {
	var req certificationRequest
	if rest, err := asn1.Unmarshal(der, &req); err != nil {
		return nil, fmt.Errorf("parse certificate request: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("parse certificate request: trailing data")
	}
	pub, err := x509.ParsePKIXPublicKey(req.Info.PublicKey.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate request public key: %w", err)
	}

	csr := &x509.CertificateRequest{
		Raw:                      der,
		RawTBSCertificateRequest: req.Info.Raw,
		RawSubjectPublicKeyInfo:  req.Info.PublicKey.FullBytes,
		RawSubject:               req.Info.Subject.FullBytes,
		PublicKey:                pub,
	}
	// The subject only names the self-signed signer certificate (see selfSign),
	// so one encoding/asn1 cannot read is left out rather than refused.
	var subject pkix.RDNSequence
	if rest, err := asn1.Unmarshal(csr.RawSubject, &subject); err == nil && len(rest) == 0 {
		csr.Subject.FillFromRDNSequence(&subject)
	}
	return csr, nil
}

// certificate is the start of an X.509 Certificate (RFC 5280).
type certificate struct {
	TBSCertificate struct {
		Version            int `asn1:"optional,explicit,default:0,tag:0"`
		SerialNumber       asn1.RawValue
		SignatureAlgorithm asn1.RawValue
		Issuer             asn1.RawValue
		Validity           asn1.RawValue
		Subject            asn1.RawValue
		PublicKey          asn1.RawValue
	}
}

// certificatePublicKey returns the subject public key of a DER certificate
// without validating its extensions.
func certificatePublicKey(der []byte) (crypto.PublicKey, error) {
	var cert certificate
	if rest, err := asn1.Unmarshal(der, &cert); err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("parse certificate: trailing data")
	}
	return x509.ParsePKIXPublicKey(cert.TBSCertificate.PublicKey.FullBytes)
}

// contentInfo is a CMS ContentInfo (RFC 5652, section 3).
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// signedData is the start of a CMS SignedData (RFC 5652, section 5.1).
type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
}

var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

// degenerateCertificates returns the DER certificates of a BER or DER encoded
// degenerate (certificates-only) SignedData, in the order they were sent.
// Other certificate choices (attribute certificates and the like) are skipped.
func degenerateCertificates(ber []byte) ([][]byte, error) {
	der, err := envelope.BERToDER(ber)
	if err != nil {
		return nil, err
	}
	var ci contentInfo
	if rest, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("parse content info: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("parse content info: trailing data")
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("unexpected content type %s, want signed data", ci.ContentType)
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("parse signed data: %w", err)
	}

	var certs [][]byte
	for rest := sd.Certificates.Bytes; len(rest) > 0; {
		var choice asn1.RawValue
		if rest, err = asn1.Unmarshal(rest, &choice); err != nil {
			return nil, fmt.Errorf("parse signed data certificates: %w", err)
		}
		if choice.Class == asn1.ClassUniversal && choice.Tag == asn1.TagSequence {
			certs = append(certs, choice.FullBytes)
		}
	}
	return certs, nil
}

// certificateForKey returns the DER certificate for key out of certs. A
// certificate whose public key cannot be read is not for an RSA key.
func certificateForKey(certs [][]byte, key *rsa.PrivateKey) ([]byte, error) {
	for _, der := range certs {
		pub, err := certificatePublicKey(der)
		if err != nil {
			continue
		}
		if pub, ok := pub.(*rsa.PublicKey); ok && pub.Equal(&key.PublicKey) {
			return der, nil
		}
	}
	return nil, fmt.Errorf("scep: none of the %d certificates in the CertRep pkiEnvelope is for the private key", len(certs))
}
