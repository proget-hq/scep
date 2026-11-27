package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"

	"github.com/micromdm/scep/v2/cryptoutil/x509util"
	"github.com/micromdm/scep/v2/envelope"
	scepserver "github.com/micromdm/scep/v2/server"
)

const testChallenge = "s3cret"

// testSCEPServer is a SCEP server, the one of this repository, that issues a
// certificate for a CSR with testChallenge. It records the envelope cipher of
// every PKIOperation by the public key of the signer.
type testSCEPServer struct {
	url    string
	caCert *x509.Certificate

	mu      sync.Mutex
	ciphers map[string]asn1.ObjectIdentifier
	// block, when set, holds PKIOperation requests until it is closed
	block chan struct{}
}

func newTestSCEPServer(t *testing.T) *testSCEPServer {
	t.Helper()
	caCert, caKey := newTestCA(t)
	signer := scepserver.CSRSignerContextFunc(func(_ context.Context, m *scep.CSRReqMessage) (*x509.Certificate, error) {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      m.CSR.Subject,
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, m.CSR.PublicKey, caKey)
		if err != nil {
			return nil, err
		}
		return x509.ParseCertificate(der)
	})
	svc, err := scepserver.NewService(caCert, caKey, scepserver.StaticChallengeMiddleware(testChallenge, signer))
	if err != nil {
		t.Fatal(err)
	}
	h := scepserver.MakeHTTPHandler(scepserver.MakeServerEndpoints(svc), svc, log.NewNopLogger())

	s := &testSCEPServer{caCert: caCert, ciphers: map[string]asn1.ObjectIdentifier{}}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("operation") == "PKIOperation" {
			msg, err := s.pkiMessage(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			s.record(t, msg)
			if s.block != nil {
				select {
				case <-s.block:
				case <-r.Context().Done():
					return
				}
			}
		}
		// The library reads the cipher of the CertRep from the variable the
		// client sets under pkcs7EncryptMu; in production the server is
		// another process.
		pkcs7EncryptMu.Lock()
		defer pkcs7EncryptMu.Unlock()
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	s.url = ts.URL + "/scep"
	return s
}

// pkiMessage reads the message of a PKIOperation and leaves it for the
// handler.
func (s *testSCEPServer) pkiMessage(r *http.Request) ([]byte, error) {
	if r.Method == http.MethodGet {
		return base64.StdEncoding.DecodeString(r.URL.Query().Get("message"))
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = ioutil.NopCloser(bytes.NewReader(body))
	return body, nil
}

func (s *testSCEPServer) record(t *testing.T, msg []byte) {
	p7, err := pkcs7.Parse(msg)
	if err != nil {
		t.Errorf("parsing pkiMessage: %s", err)
		return
	}
	ed, err := envelope.Parse(p7.Content)
	if err != nil {
		t.Errorf("parsing pkiEnvelope: %s", err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range p7.Certificates {
		s.ciphers[publicKeyID(t, c.PublicKey)] = ed.ContentEncryptionAlgorithm()
	}
}

func (s *testSCEPServer) cipher(t *testing.T, key *rsa.PrivateKey) asn1.ObjectIdentifier {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ciphers[publicKeyID(t, &key.PublicKey)]
}

func publicKeyID(t *testing.T, pub interface{}) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(der)
}

func newAPI(t *testing.T, token string, timeout time.Duration) *httptest.Server {
	t.Helper()
	s := &apiServer{logger: log.NewNopLogger(), token: token, timeout: timeout}
	ts := httptest.NewServer(s.handler())
	t.Cleanup(ts.Close)
	return ts
}

func pemKeyPKCS1(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: rsaPrivateKeyPEMBlockType, Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

func pemKeyPKCS8(t *testing.T, key interface{}) string {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func pemCSRWithChallenge(t *testing.T, key *rsa.PrivateKey, cn, challenge string) string {
	t.Helper()
	der, err := x509util.CreateCertificateRequest(rand.Reader, &x509util.CertificateRequest{
		CertificateRequest: x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}},
		ChallengePassword:  challenge,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pemCSR(der))
}

func postEnroll(t *testing.T, api *httptest.Server, token string, body interface{}) (int, map[string]string) {
	t.Helper()
	var payload []byte
	if s, ok := body.(string); ok {
		payload = []byte(s)
	} else {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(http.MethodPost, api.URL+"/v1/enroll", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	var out map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, out
}

func checkIssued(t *testing.T, pemCertificate string, key *rsa.PrivateKey, ca *x509.Certificate, cn string) {
	t.Helper()
	block, _ := pem.Decode([]byte(pemCertificate))
	if block == nil || block.Type != certificatePEMBlockType {
		t.Fatalf("certificate is not a PEM certificate: %q", pemCertificate)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if pub, ok := cert.PublicKey.(*rsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		t.Error("the certificate is not for the key")
	}
	if err := cert.CheckSignatureFrom(ca); err != nil {
		t.Errorf("the certificate is not issued by the CA: %s", err)
	}
	if cert.Subject.CommonName != cn {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, cn)
	}
}

func TestAPIEnroll(t *testing.T) {
	srv := newTestSCEPServer(t)
	api := newAPI(t, "", time.Minute)

	for _, tc := range []struct {
		encryption, signature string
		pkcs8                 bool
	}{
		{"aes128", "sha256", false},
		{"aes256", "sha512", true},
		{"des3", "sha384", false},
		{"des", "sha1", false},
		{"", "", false}, // the CLI defaults: des, sha1
	} {
		t.Run(tc.encryption+"/"+tc.signature, func(t *testing.T) {
			key := newTestKey(t)
			privateKey := pemKeyPKCS1(key)
			if tc.pkcs8 {
				privateKey = pemKeyPKCS8(t, key)
			}
			status, resp := postEnroll(t, api, "", enrollRequest{
				ServerURL:           srv.url,
				PrivateKey:          privateKey,
				CSR:                 pemCSRWithChallenge(t, key, "device-1", testChallenge),
				EncryptionAlgorithm: tc.encryption,
				SignatureAlgorithm:  tc.signature,
			})
			if status != http.StatusOK {
				t.Fatalf("status = %d, body %v", status, resp)
			}
			checkIssued(t, resp["certificate"], key, srv.caCert, "device-1")

			encryption := tc.encryption
			if encryption == "" {
				encryption = "des"
			}
			if got := srv.cipher(t, key); !got.Equal(encryptionOIDs[encryption]) {
				t.Errorf("pkiEnvelope cipher = %s, want %s", got, encryption)
			}
		})
	}
}

// Requests with different ciphers at the same time each get theirs: the pkcs7
// library takes the cipher from a package variable.
func TestAPIEnrollConcurrent(t *testing.T) {
	srv := newTestSCEPServer(t)
	api := newAPI(t, "", time.Minute)

	algorithms := []string{"des", "aes128", "aes256", "des3", "aes128", "des", "aes256", "des3"}
	keys := make([]*rsa.PrivateKey, len(algorithms))
	for i := range keys {
		keys[i] = newTestKey(t)
	}

	var wg sync.WaitGroup
	for i, alg := range algorithms {
		wg.Add(1)
		go func(i int, alg string) {
			defer wg.Done()
			cn := fmt.Sprintf("device-%d", i)
			status, resp := postEnroll(t, api, "", enrollRequest{
				ServerURL:           srv.url,
				PrivateKey:          pemKeyPKCS1(keys[i]),
				CSR:                 pemCSRWithChallenge(t, keys[i], cn, testChallenge),
				EncryptionAlgorithm: alg,
				SignatureAlgorithm:  "sha256",
			})
			if status != http.StatusOK {
				t.Errorf("%s: status = %d, body %v", cn, status, resp)
				return
			}
			checkIssued(t, resp["certificate"], keys[i], srv.caCert, cn)
		}(i, alg)
	}
	wg.Wait()

	for i, alg := range algorithms {
		if got := srv.cipher(t, keys[i]); !got.Equal(encryptionOIDs[alg]) {
			t.Errorf("device-%d: pkiEnvelope cipher = %s, want %s", i, got, alg)
		}
	}
}

func TestAPIEnrollFailure(t *testing.T) {
	srv := newTestSCEPServer(t)
	api := newAPI(t, "", time.Minute)

	key := newTestKey(t)
	status, resp := postEnroll(t, api, "", enrollRequest{
		ServerURL:           srv.url,
		PrivateKey:          pemKeyPKCS1(key),
		CSR:                 pemCSRWithChallenge(t, key, "device-1", "wrong"),
		EncryptionAlgorithm: "aes128",
		SignatureAlgorithm:  "sha256",
	})
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502, body %v", status, resp)
	}
	if resp["fail_info"] != string(scep.BadRequest) {
		t.Errorf("fail_info = %q, want %q", resp["fail_info"], scep.BadRequest)
	}
	if !strings.Contains(resp["error"], "request failed, failInfo: badRequest") {
		t.Errorf("error = %q", resp["error"])
	}
}

func TestAPIEnrollUnreachableServer(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	url := ts.URL + "/scep"
	ts.Close()
	api := newAPI(t, "", time.Minute)

	key := newTestKey(t)
	status, resp := postEnroll(t, api, "", enrollRequest{
		ServerURL:  url,
		PrivateKey: pemKeyPKCS1(key),
		CSR:        pemCSRWithChallenge(t, key, "device-1", testChallenge),
	})
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502, body %v", status, resp)
	}
	if !strings.Contains(resp["error"], "GetCACert") {
		t.Errorf("error = %q", resp["error"])
	}
}

func TestAPIEnrollTimeout(t *testing.T) {
	srv := newTestSCEPServer(t)
	srv.block = make(chan struct{})
	defer close(srv.block)
	api := newAPI(t, "", 200*time.Millisecond)

	key := newTestKey(t)
	status, resp := postEnroll(t, api, "", enrollRequest{
		ServerURL:  srv.url,
		PrivateKey: pemKeyPKCS1(key),
		CSR:        pemCSRWithChallenge(t, key, "device-1", testChallenge),
	})
	if status != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504, body %v", status, resp)
	}
	if !strings.Contains(resp["error"], "did not finish within 200ms") {
		t.Errorf("error = %q", resp["error"])
	}
}

func TestAPIEnrollBadRequest(t *testing.T) {
	api := newAPI(t, "", time.Minute)
	key := newTestKey(t)
	other := newTestKey(t)
	valid := func() enrollRequest {
		return enrollRequest{
			ServerURL:  "http://scep.example/scep",
			PrivateKey: pemKeyPKCS1(key),
			CSR:        pemCSRWithChallenge(t, key, "device-1", testChallenge),
		}
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecKey := pemKeyPKCS8(t, ec)

	for name, tc := range map[string]struct {
		body interface{}
		want string
	}{
		"not JSON":        {"{", "invalid JSON body"},
		"unknown field":   {`{"server_url":"http://x/scep","challenge":"x"}`, "unknown field"},
		"no server_url":   {func() enrollRequest { r := valid(); r.ServerURL = ""; return r }(), "server_url is required"},
		"relative url":    {func() enrollRequest { r := valid(); r.ServerURL = "scep.example/scep"; return r }(), "absolute http(s) URL"},
		"ftp url":         {func() enrollRequest { r := valid(); r.ServerURL = "ftp://scep.example/scep"; return r }(), "absolute http(s) URL"},
		"no key":          {func() enrollRequest { r := valid(); r.PrivateKey = ""; return r }(), "private_key: no PEM block"},
		"EC key":          {func() enrollRequest { r := valid(); r.PrivateKey = ecKey; return r }(), "private_key: not an RSA key"},
		"cert as key":     {func() enrollRequest { r := valid(); r.PrivateKey = r.CSR; return r }(), "private_key: unexpected PEM block"},
		"no CSR":          {func() enrollRequest { r := valid(); r.CSR = ""; return r }(), "csr: no PEM block"},
		"key as CSR":      {func() enrollRequest { r := valid(); r.CSR = r.PrivateKey; return r }(), "csr: unexpected PEM block"},
		"CSR of other":    {func() enrollRequest { r := valid(); r.PrivateKey = pemKeyPKCS1(other); return r }(), "csr is not for private_key"},
		"bad encryption":  {func() enrollRequest { r := valid(); r.EncryptionAlgorithm = "rc2"; return r }(), "invalid encryption_algorithm: rc2"},
		"bad signature":   {func() enrollRequest { r := valid(); r.SignatureAlgorithm = "md5"; return r }(), "invalid signature_algorithm: md5"},
		"bad fingerprint": {func() enrollRequest { r := valid(); r.CAFingerprint = "abcd"; return r }(), "invalid ca_fingerprint"},
		"two selectors": {func() enrollRequest {
			r := valid()
			r.CAFingerprint = strings.Repeat("ab", 32)
			r.KeyEnciphermentSelector = true
			return r
		}(), "can't be used at the same time"},
	} {
		t.Run(name, func(t *testing.T) {
			status, resp := postEnroll(t, api, "", tc.body)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body %v", status, resp)
			}
			if !strings.Contains(resp["error"], tc.want) {
				t.Errorf("error = %q, want it to contain %q", resp["error"], tc.want)
			}
		})
	}
}

func TestAPIToken(t *testing.T) {
	srv := newTestSCEPServer(t)
	api := newAPI(t, "t0ken", time.Minute)
	key := newTestKey(t)
	req := enrollRequest{
		ServerURL:  srv.url,
		PrivateKey: pemKeyPKCS1(key),
		CSR:        pemCSRWithChallenge(t, key, "device-1", testChallenge),
	}

	for _, token := range []string{"", "wrong", "t0ken0"} {
		if status, _ := postEnroll(t, api, token, req); status != http.StatusUnauthorized {
			t.Errorf("token %q: status = %d, want 401", token, status)
		}
	}
	if status, resp := postEnroll(t, api, "t0ken", req); status != http.StatusOK {
		t.Errorf("status = %d, body %v", status, resp)
	}

	// the health check needs no token
	resp, err := http.Get(api.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz status = %d", resp.StatusCode)
	}
}

func TestAPIMethods(t *testing.T) {
	api := newAPI(t, "", time.Minute)
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/v1/enroll", http.StatusMethodNotAllowed},
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/other", http.StatusNotFound},
	} {
		req, _ := http.NewRequest(tc.method, api.URL+tc.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("%s %s: status = %d, want %d", tc.method, tc.path, resp.StatusCode, tc.want)
		}
	}
}
