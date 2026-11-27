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
	"sync"

	"github.com/go-kit/kit/log"
	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"

	"github.com/micromdm/scep/v2/cryptoutil"
	"github.com/micromdm/scep/v2/cryptoutil/x509util"
	"github.com/micromdm/scep/v2/envelope"
)

var (
	oidSCEPmessageType   = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidSCEPsenderNonce   = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidSCEPtransactionID = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
)

// envelopeEncrypter encrypts the pkiMessage content for the CA/RA recipients.
type envelopeEncrypter func(content []byte, recipients []*x509.Certificate) ([]byte, error)

// encryptionAlgorithms maps -encryption-algorithm values to encrypters.
// "des" keeps the upstream behaviour. The pkcs7 library encrypts neither
// DES-EDE3 nor AES-192, so the envelope package does.
var encryptionAlgorithms = map[string]envelopeEncrypter{
	"des":    pkcs7Encrypter(pkcs7.EncryptionAlgorithmDESCBC),
	"des3":   envelope.DESEDE3CBC.Encrypt,
	"aes128": pkcs7Encrypter(pkcs7.EncryptionAlgorithmAES128CBC),
	"aes192": envelope.AES192CBC.Encrypt,
	"aes256": pkcs7Encrypter(pkcs7.EncryptionAlgorithmAES256CBC),
}

// pkcs7EncryptMu guards pkcs7.ContentEncryptionAlgorithm: the library takes
// the cipher from a package variable, and the API server builds messages
// concurrently.
var pkcs7EncryptMu sync.Mutex

// pkcs7Encrypter encrypts with the pkcs7 library.
func pkcs7Encrypter(alg int) envelopeEncrypter {
	return func(content []byte, recipients []*x509.Certificate) ([]byte, error) {
		pkcs7EncryptMu.Lock()
		defer pkcs7EncryptMu.Unlock()
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

// decryptCertRep returns the certificate issued in a successful CertRep: the
// one for key out of the certificates in the envelope, which some servers fill
// with the chain, not always issued certificate first. The certificates are
// read with x509util.ParseCertificate, so one crypto/x509 refuses for its
// extensions (say, a subjectAltName that is not ASCII) is returned as well.
// The envelope is inspected first: the ones the pkcs7 library cannot open (see
// envelope.EnvelopedData.UnsupportedByPKCS7) are decrypted by the envelope
// package, all others by the library.
func decryptCertRep(respMsg *scep.PKIMessage, cert *x509.Certificate, key *rsa.PrivateKey) (*x509.Certificate, error) {
	content, err := decryptCertRepEnvelope(respMsg, cert, key)
	if err != nil {
		return nil, err
	}
	certs, err := envelope.DegenerateCertificates(content)
	if err != nil {
		return nil, err
	}
	return certificateForKey(certs, key)
}

// certificateForKey returns the certificate for key out of the DER certs. One
// that cannot be parsed is not for key; the first such error is reported when
// none is.
func certificateForKey(certs [][]byte, key *rsa.PrivateKey) (*x509.Certificate, error) {
	var parseErr error
	for _, der := range certs {
		c, err := x509util.ParseCertificate(der)
		if err != nil {
			if parseErr == nil {
				parseErr = err
			}
			continue
		}
		if pub, ok := c.PublicKey.(*rsa.PublicKey); ok && pub.Equal(&key.PublicKey) {
			return c, nil
		}
	}
	err := fmt.Errorf("scep: none of the %d certificates in the CertRep pkiEnvelope is for the private key", len(certs))
	if parseErr != nil {
		err = fmt.Errorf("%w (%v)", err, parseErr)
	}
	return nil, err
}

func decryptCertRepEnvelope(respMsg *scep.PKIMessage, cert *x509.Certificate, key *rsa.PrivateKey) ([]byte, error) {
	ed, parseErr := certRepEnvelope(respMsg)
	if parseErr == nil && ed.UnsupportedByPKCS7(cert) {
		return ed.Decrypt(cert, key)
	}

	// What respMsg.DecryptPKIEnvelope does, which keeps only the first
	// certificate. If our parser failed, the library may still read the
	// envelope; when it cannot either, report both errors.
	content, err := pkcs7Decrypt(respMsg, cert, key)
	if err != nil {
		if parseErr != nil {
			return nil, fmt.Errorf("%w (%v)", err, parseErr)
		}
		return nil, err
	}
	return content, nil
}

func pkcs7Decrypt(respMsg *scep.PKIMessage, cert *x509.Certificate, key *rsa.PrivateKey) ([]byte, error) {
	signed, err := pkcs7.Parse(respMsg.Raw)
	if err != nil {
		return nil, err
	}
	enveloped, err := pkcs7.Parse(signed.Content)
	if err != nil {
		return nil, err
	}
	return enveloped.Decrypt(cert, key)
}

// certRepEnvelope parses the EnvelopedData signed in a CertRep.
func certRepEnvelope(respMsg *scep.PKIMessage) (*envelope.EnvelopedData, error) {
	p7, err := pkcs7.Parse(respMsg.Raw)
	if err != nil {
		return nil, err
	}
	return envelope.Parse(p7.Content)
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
