package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/go-kit/kit/log"
	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"

	"github.com/micromdm/scep/v2/cryptoutil"
)

var (
	oidSCEPmessageType   = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidSCEPsenderNonce   = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidSCEPtransactionID = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
)

// envelopeEncrypter encrypts the pkiMessage content for the CA/RA recipients.
type envelopeEncrypter func(content []byte, recipients []*x509.Certificate) ([]byte, error)

// encryptionAlgorithms maps -encryption-algorithm values to encrypters.
// "des" keeps the upstream behaviour. Only AES-192 needs our own encrypter.
var encryptionAlgorithms = map[string]envelopeEncrypter{
	"des":    pkcs7Encrypter(pkcs7.EncryptionAlgorithmDESCBC),
	"aes128": pkcs7Encrypter(pkcs7.EncryptionAlgorithmAES128CBC),
	"aes192": aesCBCAlgorithms[1].encrypt,
	"aes256": pkcs7Encrypter(pkcs7.EncryptionAlgorithmAES256CBC),
}

// pkcs7Encrypter encrypts with the pkcs7 library. The library takes the cipher
// from a package variable, which is fine for a CLI building one message at a
// time.
func pkcs7Encrypter(alg int) envelopeEncrypter {
	return func(content []byte, recipients []*x509.Certificate) ([]byte, error) {
		pkcs7.ContentEncryptionAlgorithm = alg
		return pkcs7.Encrypt(content, recipients)
	}
}

// signatureAlgorithms maps -signature-algorithm values to digest OIDs.
var signatureAlgorithms = map[string]asn1.ObjectIdentifier{
	"sha1":   pkcs7.OIDDigestAlgorithmSHA1,
	"sha256": pkcs7.OIDDigestAlgorithmSHA256,
	"sha384": pkcs7.OIDDigestAlgorithmSHA384,
	"sha512": pkcs7.OIDDigestAlgorithmSHA512,
}

// newCSRRequest builds the DER encoded pkiMessage for a PKCSReq/RenewalReq.
// It mirrors scep.NewCSRRequest, which hardcodes DES-CBC for the envelope and
// SHA-1 for the signature; here both are chosen by the caller.
func newCSRRequest(
	csr *x509.CertificateRequest,
	tmpl *scep.PKIMessage,
	selector scep.CertsSelector,
	encrypt envelopeEncrypter,
	digest asn1.ObjectIdentifier,
	logger log.Logger,
) ([]byte, error) {
	recipients := selector.SelectCerts(tmpl.Recipients)
	if len(recipients) < 1 {
		if len(tmpl.Recipients) >= 1 {
			return nil, errors.New("scep: no selected CA/RA recipients")
		}
		return nil, errors.New("scep: no CA/RA recipients")
	}

	e7, err := encrypt(csr.Raw, recipients)
	if err != nil {
		return nil, fmt.Errorf("encrypt pkiEnvelope: %w", err)
	}

	signedData, err := pkcs7.NewSignedData(e7)
	if err != nil {
		return nil, err
	}
	signedData.SetDigestAlgorithm(digest)

	tID, err := newTransactionID(csr.PublicKey)
	if err != nil {
		return nil, err
	}
	sn, err := newNonce()
	if err != nil {
		return nil, err
	}

	logger.Log(
		"msg", "creating SCEP CSR request",
		"transaction_id", tID,
		"signer_cn", tmpl.SignerCert.Subject.CommonName,
		"digest", digest.String(),
	)

	config := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: []pkcs7.Attribute{
			{Type: oidSCEPtransactionID, Value: tID},
			{Type: oidSCEPmessageType, Value: tmpl.MessageType},
			{Type: oidSCEPsenderNonce, Value: sn},
		},
	}
	if err := signedData.AddSigner(tmpl.SignerCert, tmpl.SignerKey, config); err != nil {
		return nil, err
	}

	return signedData.Finish()
}

// decryptCertRep returns the certificate issued in a successful CertRep. The
// envelope is inspected first: the ones the pkcs7 library cannot open (see
// needsOwnDecrypter) are decrypted here, all others by DecryptPKIEnvelope.
func decryptCertRep(respMsg *scep.PKIMessage, cert *x509.Certificate, key *rsa.PrivateKey) (*x509.Certificate, error) {
	ed, parseErr := certRepEnvelope(respMsg)
	if parseErr == nil && ed.needsOwnDecrypter(cert) {
		envelope, err := ed.decrypt(cert, key)
		if err != nil {
			return nil, err
		}
		certs, err := scep.CACerts(envelope)
		if err != nil {
			return nil, err
		}
		if len(certs) == 0 {
			return nil, errors.New("scep: no certificate in the CertRep pkiEnvelope")
		}
		return certs[0], nil
	}

	// If our parser failed, the library may still read the envelope; when it
	// cannot either, report both errors.
	if err := respMsg.DecryptPKIEnvelope(cert, key); err != nil {
		if parseErr != nil {
			return nil, fmt.Errorf("%w (%v)", err, parseErr)
		}
		return nil, err
	}
	return respMsg.CertRepMessage.Certificate, nil
}

// certRepEnvelope parses the EnvelopedData signed in a CertRep.
func certRepEnvelope(respMsg *scep.PKIMessage) (*envelopedData, error) {
	p7, err := pkcs7.Parse(respMsg.Raw)
	if err != nil {
		return nil, err
	}
	return parseEnvelope(p7.Content)
}

func newNonce() (scep.SenderNonce, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return scep.SenderNonce(b), nil
}

// newTransactionID derives a deterministic transactionID from the public key.
func newTransactionID(key crypto.PublicKey) (scep.TransactionID, error) {
	id, err := cryptoutil.GenerateSubjectKeyID(key)
	if err != nil {
		return "", err
	}
	return scep.TransactionID(base64.StdEncoding.EncodeToString(id)), nil
}
