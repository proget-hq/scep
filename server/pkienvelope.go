package scepserver

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/go-kit/kit/log"
	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
	"github.com/smallstep/scep/x509util"

	"github.com/micromdm/scep/v2/envelope"
)

// decryptPKIEnvelope fills msg.CSRReqMessage from the request's pkiEnvelope.
// The envelope is inspected first: CSR requests the pkcs7 library cannot open
// (AES-192, RSAES-OAEP key transport, see envelope.EnvelopedData.UnsupportedByPKCS7)
// are decrypted by the envelope package, everything else by
// msg.DecryptPKIEnvelope. The library unwraps the content key before it looks
// at the content cipher, so its errors cannot be used to fall back afterwards.
func decryptPKIEnvelope(msg *scep.PKIMessage, cert *x509.Certificate, key *rsa.PrivateKey, logger log.Logger) error {
	switch msg.MessageType {
	case scep.PKCSReq, scep.UpdateReq, scep.RenewalReq:
	default:
		return msg.DecryptPKIEnvelope(cert, key)
	}

	ed, parseErr := requestEnvelope(msg)
	if parseErr != nil || !ed.UnsupportedByPKCS7(cert) {
		// If our parser failed, the library may still read the envelope; when
		// it cannot either, report both errors.
		if err := msg.DecryptPKIEnvelope(cert, key); err != nil {
			if parseErr != nil {
				return fmt.Errorf("%w (%v)", err, parseErr)
			}
			return err
		}
		return nil
	}

	// what msg.DecryptPKIEnvelope does for CSR requests
	content, err := ed.Decrypt(cert, key)
	if err != nil {
		return err
	}
	csr, err := x509.ParseCertificateRequest(content)
	if err != nil {
		return fmt.Errorf("scep: parse CSR from pkiEnvelope: %w", err)
	}
	cp, err := x509util.ParseChallengePassword(content)
	if err != nil {
		return fmt.Errorf("scep: parse challenge password in pkiEnvelope: %w", err)
	}
	msg.CSRReqMessage = &scep.CSRReqMessage{
		RawDecrypted:      content,
		CSR:               csr,
		ChallengePassword: cp,
	}
	logger.Log(
		"msg", "decrypt pkiEnvelope",
		"content_encryption", ed.ContentEncryptionAlgorithm().String(),
		"has_challenge", cp != "",
	)
	return nil
}

// requestEnvelope parses the EnvelopedData signed in a pkiMessage.
func requestEnvelope(msg *scep.PKIMessage) (*envelope.EnvelopedData, error) {
	p7, err := pkcs7.Parse(msg.Raw)
	if err != nil {
		return nil, err
	}
	return envelope.Parse(p7.Content)
}
