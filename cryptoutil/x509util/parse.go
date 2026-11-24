package x509util

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// crypto/x509 refuses requests and certificates whose subjectAltName holds an
// rfc822Name, dNSName or URI that is not ASCII, which OpenSSL writes as given,
// and the like. ParseCertificateRequest and ParseCertificate read those too:
// when crypto/x509 refuses the DER, they check its ASN.1 structure only, down
// to the subject, issuer and public key, leaving the content of attributes and
// extensions unchecked.

// ParseCertificateRequest parses a DER certificate request like
// x509.ParseCertificateRequest. A request crypto/x509 refuses but whose ASN.1
// structure is sound is returned with only Raw, RawTBSCertificateRequest,
// RawSubjectPublicKeyInfo, RawSubject, Version, Signature, Subject and
// PublicKey set.
func ParseCertificateRequest(der []byte) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err == nil {
		return csr, nil
	}
	csr, rawErr := parseRawCertificateRequest(der)
	if rawErr != nil {
		return nil, fmt.Errorf("%w (%v)", err, rawErr)
	}
	return csr, nil
}

func parseRawCertificateRequest(der []byte) (*x509.CertificateRequest, error) {
	var req certificateRequest
	if rest, err := asn1.Unmarshal(der, &req); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}
	pub, err := x509.ParsePKIXPublicKey(req.TBSCSR.PublicKey.Raw)
	if err != nil {
		return nil, err
	}
	subject, err := parseName(req.TBSCSR.Subject.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("subject: %w", err)
	}
	return &x509.CertificateRequest{
		Raw:                      req.Raw,
		RawTBSCertificateRequest: req.TBSCSR.Raw,
		RawSubjectPublicKeyInfo:  req.TBSCSR.PublicKey.Raw,
		RawSubject:               req.TBSCSR.Subject.FullBytes,
		Version:                  req.TBSCSR.Version,
		Signature:                req.SignatureValue.RightAlign(),
		PublicKey:                pub,
		Subject:                  subject,
	}, nil
}

// ParseCertificate parses a DER certificate like x509.ParseCertificate. A
// certificate crypto/x509 refuses but whose ASN.1 structure is sound is
// returned with only Raw, RawTBSCertificate, RawSubjectPublicKeyInfo,
// RawSubject, RawIssuer, Version, SerialNumber, Signature, Issuer, Subject,
// NotBefore, NotAfter, PublicKey and Extensions set.
func ParseCertificate(der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err == nil {
		return cert, nil
	}
	cert, rawErr := parseRawCertificate(der)
	if rawErr != nil {
		return nil, fmt.Errorf("%w (%v)", err, rawErr)
	}
	return cert, nil
}

func parseRawCertificate(der []byte) (*x509.Certificate, error) {
	var c certificate
	if rest, err := asn1.Unmarshal(der, &c); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}
	tbs := &c.TBSCertificate
	pub, err := x509.ParsePKIXPublicKey(tbs.PublicKey.Raw)
	if err != nil {
		return nil, err
	}
	issuer, err := parseName(tbs.Issuer.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}
	subject, err := parseName(tbs.Subject.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("subject: %w", err)
	}
	return &x509.Certificate{
		Raw:                     c.Raw,
		RawTBSCertificate:       tbs.Raw,
		RawSubjectPublicKeyInfo: tbs.PublicKey.Raw,
		RawSubject:              tbs.Subject.FullBytes,
		RawIssuer:               tbs.Issuer.FullBytes,
		Version:                 tbs.Version + 1,
		SerialNumber:            tbs.SerialNumber,
		Signature:               c.SignatureValue.RightAlign(),
		Issuer:                  issuer,
		Subject:                 subject,
		NotBefore:               tbs.Validity.NotBefore,
		NotAfter:                tbs.Validity.NotAfter,
		PublicKey:               pub,
		Extensions:              tbs.Extensions,
	}, nil
}

// parseName parses a DER Name; the names crypto/x509 reads, so does this.
func parseName(der []byte) (pkix.Name, error) {
	var rdns pkix.RDNSequence
	if rest, err := asn1.Unmarshal(der, &rdns); err != nil {
		return pkix.Name{}, err
	} else if len(rest) != 0 {
		return pkix.Name{}, asn1.SyntaxError{Msg: "trailing data"}
	}
	var name pkix.Name
	name.FillFromRDNSequence(&rdns)
	return name, nil
}

// The structures below are copied from the Go standard library x509 package,
// from before it moved to cryptobyte.

type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueID           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueID    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"omitempty,optional,explicit,tag:3"`
}

type validity struct {
	NotBefore, NotAfter time.Time
}
