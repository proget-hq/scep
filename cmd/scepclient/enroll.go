package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/smallstep/scep"

	scepclient "github.com/micromdm/scep/v2/client"
)

// pendingRetryInterval is the pause before a request the server answered
// PENDING is sent again.
var pendingRetryInterval = 30 * time.Second

// enrollment is one PKCSReq (or RenewalReq) to a SCEP server, everything the
// CLI reads from files and flags and the API from the request body.
type enrollment struct {
	key *rsa.PrivateKey
	csr *x509.CertificateRequest
	// signerCert signs the pkiMessage: the certificate to renew for a
	// RenewalReq, a certificate self-signed with key for a PKCSReq.
	signerCert *x509.Certificate
	msgType    scep.MessageType

	caCertMsg       string
	caCertsSelector scep.CertsSelector
	encrypt         envelopeEncrypter
	digest          asn1.ObjectIdentifier
}

// failureError is a CertRep with pkiStatus FAILURE.
type failureError struct {
	msgType  scep.MessageType
	failInfo scep.FailInfo
}

func (e *failureError) Error() string {
	return fmt.Sprintf("%s request failed, failInfo: %s", e.msgType, e.failInfo)
}

// enroll fetches the CA/RA certificates, sends the request and returns the
// issued certificate. A PENDING answer is polled every pendingRetryInterval
// until ctx is done.
func enroll(ctx context.Context, client scepclient.Client, e enrollment, logger log.Logger, debug bool) (*x509.Certificate, error) {
	resp, certNum, err := client.GetCACert(ctx, e.caCertMsg)
	if err != nil {
		return nil, fmt.Errorf("GetCACert: %w", err)
	}
	var caCerts []*x509.Certificate
	if certNum > 1 {
		caCerts, err = scep.CACerts(resp)
	} else {
		caCerts, err = x509.ParseCertificates(resp)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing GetCACert response: %w", err)
	}

	if debug {
		logCerts(level.Debug(logger), caCerts)
	}

	tmpl := &scep.PKIMessage{
		MessageType: e.msgType,
		Recipients:  caCerts,
		SignerKey:   e.key,
		SignerCert:  e.signerCert,
	}

	msg, err := newCSRRequest(e.csr, tmpl, e.caCertsSelector, e.encrypt, e.digest, logger)
	if err != nil {
		return nil, fmt.Errorf("creating csr pkiMessage: %w", err)
	}

	var respMsg *scep.PKIMessage
	for {
		// loop in case we get a PENDING response which requires
		// a manual approval.

		respBytes, err := client.PKIOperation(ctx, msg)
		if err != nil {
			return nil, fmt.Errorf("PKIOperation for %s: %w", e.msgType, err)
		}

		respMsg, err = scep.ParsePKIMessage(respBytes, scep.WithLogger(logger), scep.WithCACerts(caCerts))
		if err != nil {
			return nil, fmt.Errorf("parsing pkiMessage response %s: %w", e.msgType, err)
		}

		if respMsg.PKIStatus == scep.FAILURE {
			return nil, &failureError{msgType: e.msgType, failInfo: respMsg.FailInfo}
		}
		if respMsg.PKIStatus != scep.PENDING {
			break // on scep.SUCCESS
		}

		level.Info(logger).Log("pkiStatus", "PENDING", "msg", fmt.Sprintf("sleeping for %s, then trying again.", pendingRetryInterval))
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%s request still PENDING: %w", e.msgType, ctx.Err())
		case <-time.After(pendingRetryInterval):
		}
	}
	level.Info(logger).Log("pkiStatus", "SUCCESS", "msg", "server returned a certificate.")

	cert, err := decryptCertRep(respMsg, e.signerCert, e.key)
	if err != nil {
		return nil, fmt.Errorf("decrypt pkiEnvelope, msgType: %s, status %s: %w", e.msgType, respMsg.PKIStatus, err)
	}
	return cert, nil
}
