package envelope

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/smallstep/pkcs7"
)

// signedData is a CMS SignedData (RFC 5652, section 5.1) whose certificates
// and CRLs are kept as they were sent.
type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo contentInfo
	Certificates     []asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             []asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []asn1.RawValue `asn1:"set"`
}

// DegenerateCertificates returns the certificates of a BER or DER encoded
// ContentInfo holding a degenerate (certificates-only) SignedData, such as the
// content of a CertRep envelope, in the order they were sent. They are
// returned as DER and are not parsed, so that the caller can read the ones
// crypto/x509 refuses (see x509util.ParseCertificate). Other certificate
// choices (attribute certificates and the like) are skipped. Signers, if any,
// are not checked.
func DegenerateCertificates(ber []byte) ([][]byte, error) {
	content, err := parseContentInfo(ber, pkcs7.OIDSignedData)
	if err != nil {
		return nil, err
	}
	var sd signedData
	if rest, err := asn1.Unmarshal(content, &sd); err != nil {
		return nil, fmt.Errorf("envelope: parse signed data: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("envelope: trailing data after signed data")
	}
	var certs [][]byte
	for _, choice := range sd.Certificates {
		if choice.Class == asn1.ClassUniversal && choice.Tag == asn1.TagSequence {
			certs = append(certs, choice.FullBytes)
		}
	}
	return certs, nil
}
