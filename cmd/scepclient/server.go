package main

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/smallstep/scep"

	scepclient "github.com/micromdm/scep/v2/client"
	"github.com/micromdm/scep/v2/cryptoutil/x509util"
)

// apiTokenEnv names the environment variable with the bearer token the API
// requires. It is not a flag so it does not show in the process list.
const apiTokenEnv = "SCEPCLIENT_API_TOKEN"

// maxEnrollRequestSize bounds the JSON body of an enroll request: a key and a
// CSR are a few kilobytes.
const maxEnrollRequestSize = 1 << 20

// enrollRequest is the body of POST /v1/enroll. The algorithm and selector
// fields take the values of the CLI flags of the same name.
type enrollRequest struct {
	ServerURL string `json:"server_url"`
	// PrivateKey is a PEM RSA key, PKCS #1 or PKCS #8.
	PrivateKey string `json:"private_key"`
	// CSR is a PEM certificate request signed with PrivateKey; a challenge
	// password the server wants is an attribute of it.
	CSR                     string `json:"csr"`
	CACertMessage           string `json:"cacert_message"`
	EncryptionAlgorithm     string `json:"encryption_algorithm"`
	SignatureAlgorithm      string `json:"signature_algorithm"`
	CAFingerprint           string `json:"ca_fingerprint"`
	KeyEnciphermentSelector bool   `json:"key_encipherment_selector"`
}

type enrollResponse struct {
	// Certificate is the issued certificate, PEM.
	Certificate string `json:"certificate"`
}

type errorResponse struct {
	Error string `json:"error"`
	// FailInfo is set when the SCEP server answered with pkiStatus FAILURE.
	FailInfo string `json:"fail_info,omitempty"`
}

// requestError is a problem with the enroll request itself.
type requestError struct{ msg string }

func (e *requestError) Error() string { return e.msg }

// timeoutError is an enrollment that did not finish within the API timeout,
// whichever step it was at: the deadline may surface as any transport error.
type timeoutError struct {
	err     error
	timeout time.Duration
}

func (e *timeoutError) Error() string {
	return fmt.Sprintf("enrollment did not finish within %s: %s", e.timeout, e.err)
}

func badRequest(format string, a ...interface{}) error {
	return &requestError{msg: fmt.Sprintf(format, a...)}
}

type apiServer struct {
	logger  log.Logger
	debug   bool
	token   string
	timeout time.Duration
}

func (s *apiServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)
	mux.Handle("/v1/enroll", s.authenticated(http.HandlerFunc(s.enroll)))
	return mux
}

func (s *apiServer) healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": version})
}

func (s *apiServer) authenticated(next http.Handler) http.Handler {
	if s.token == "" {
		return next
	}
	want := []byte("Bearer " + s.token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *apiServer) enroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}

	begin := time.Now()
	var req enrollRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEnrollRequestSize))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.fail(w, req, begin, badRequest("invalid JSON body: %s", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.timeout)
	defer cancel()

	cert, err := s.doEnroll(ctx, req)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded && r.Context().Err() == nil {
			err = &timeoutError{err: err, timeout: s.timeout}
		}
		s.fail(w, req, begin, err)
		return
	}

	level.Info(s.logger).Log(
		"msg", "enrolled",
		"server_url", redactedURL(req.ServerURL),
		"encryption_algorithm", req.EncryptionAlgorithm,
		"signature_algorithm", req.SignatureAlgorithm,
		"subject", cert.Subject.String(),
		"serial", cert.SerialNumber.String(),
		"took", time.Since(begin),
	)
	writeJSON(w, http.StatusOK, enrollResponse{Certificate: string(pemCert(cert.Raw))})
}

func (s *apiServer) doEnroll(ctx context.Context, req enrollRequest) (*x509.Certificate, error) {
	e, err := parseEnrollRequest(req)
	if err != nil {
		return nil, err
	}

	logger := log.With(s.logger, "server_url", redactedURL(req.ServerURL))
	client, err := scepclient.New(req.ServerURL, logger)
	if err != nil {
		return nil, badRequest("invalid server_url: %s", err)
	}
	return enroll(ctx, client, e, logger, s.debug)
}

// parseEnrollRequest checks the request and turns it into a PKCSReq signed
// with a certificate self-signed with the key, as the CLI sends when there is
// no certificate to renew.
func parseEnrollRequest(req enrollRequest) (enrollment, error) {
	if req.ServerURL == "" {
		return enrollment{}, badRequest("server_url is required")
	}
	u, err := url.Parse(req.ServerURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return enrollment{}, badRequest("server_url must be an absolute http(s) URL")
	}

	key, err := parsePrivateKey(req.PrivateKey)
	if err != nil {
		return enrollment{}, badRequest("private_key: %s", err)
	}
	csr, err := parseCSR(req.CSR)
	if err != nil {
		return enrollment{}, badRequest("csr: %s", err)
	}
	if pub, ok := csr.PublicKey.(*rsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return enrollment{}, badRequest("csr is not for private_key")
	}

	encryptionAlgorithm := req.EncryptionAlgorithm
	if encryptionAlgorithm == "" {
		encryptionAlgorithm = "des"
	}
	encrypt, ok := encryptionAlgorithms[encryptionAlgorithm]
	if !ok {
		return enrollment{}, badRequest("invalid encryption_algorithm: %s", req.EncryptionAlgorithm)
	}
	signatureAlgorithm := req.SignatureAlgorithm
	if signatureAlgorithm == "" {
		signatureAlgorithm = "sha1"
	}
	digest, ok := signatureAlgorithms[signatureAlgorithm]
	if !ok {
		return enrollment{}, badRequest("invalid signature_algorithm: %s", req.SignatureAlgorithm)
	}

	selector := scep.NopCertsSelector()
	switch {
	case req.CAFingerprint != "" && req.KeyEnciphermentSelector:
		return enrollment{}, badRequest("ca_fingerprint and key_encipherment_selector can't be used at the same time")
	case req.CAFingerprint != "":
		hash, err := validateFingerprint(req.CAFingerprint)
		if err != nil {
			return enrollment{}, badRequest("invalid ca_fingerprint: %s", err)
		}
		selector = scep.FingerprintCertsSelector(fingerprintHashType, hash)
	case req.KeyEnciphermentSelector:
		selector = scep.EnciphermentCertsSelector()
	}

	self, err := selfSign(key, csr)
	if err != nil {
		return enrollment{}, fmt.Errorf("self-signing the signer certificate: %w", err)
	}

	return enrollment{
		key:             key,
		csr:             csr,
		signerCert:      self,
		msgType:         scep.PKCSReq,
		caCertMsg:       req.CACertMessage,
		caCertsSelector: selector,
		encrypt:         encrypt,
		digest:          digest,
	}, nil
}

func parsePrivateKey(data string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	switch block.Type {
	case rsaPrivateKeyPEMBlockType:
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA key")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
	}
}

func parseCSR(data string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if block.Type != csrPEMBlockType {
		return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
	}
	return x509util.ParseCertificateRequest(block.Bytes)
}

// fail answers 400 for a bad request, 502 for a SCEP server that failed or
// refused it and 504 for one that did not answer in time (or kept it PENDING).
func (s *apiServer) fail(w http.ResponseWriter, req enrollRequest, begin time.Time, err error) {
	status := http.StatusBadGateway
	resp := errorResponse{Error: err.Error()}
	var reqErr *requestError
	var failure *failureError
	switch {
	case errors.As(err, &reqErr):
		status = http.StatusBadRequest
	case errors.As(err, &failure):
		resp.FailInfo = string(failure.failInfo)
	case errors.As(err, new(*timeoutError)):
		status = http.StatusGatewayTimeout
	}

	level.Error(s.logger).Log(
		"msg", "enroll failed",
		"server_url", redactedURL(req.ServerURL),
		"encryption_algorithm", req.EncryptionAlgorithm,
		"signature_algorithm", req.SignatureAlgorithm,
		"status", status,
		"err", err,
		"took", time.Since(begin),
	)
	writeJSON(w, status, resp)
}

// redactedURL is rawURL for the log, without a password it may carry.
func redactedURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "(invalid)"
	}
	return u.Redacted()
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// serve runs the enroll API until it fails.
func serve(addr string, timeout time.Duration, logger log.Logger, debug bool) error {
	s := &apiServer{
		logger:  logger,
		debug:   debug,
		token:   strings.TrimSpace(os.Getenv(apiTokenEnv)),
		timeout: timeout,
	}
	if s.token == "" {
		level.Info(logger).Log("msg", apiTokenEnv+" is not set, the API does not require a token")
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// an enrollment may take the whole timeout
		WriteTimeout: timeout + 10*time.Second,
		IdleTimeout:  2 * time.Minute,
	}
	level.Info(logger).Log("msg", "serving the enroll API", "addr", addr, "version", version, "timeout", timeout)
	return srv.ListenAndServe()
}
