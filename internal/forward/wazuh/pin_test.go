package wazuh

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// tlsManager stands up a TLS server that speaks just enough of the Wazuh API,
// and returns its URL together with the pin of the key it presents.
func tlsManager(t *testing.T) (url, pin string, srv *httptest.Server) {
	t.Helper()
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/security/user/authenticate"):
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"token": "t"}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"error": 0})
		}
	}))
	t.Cleanup(srv.Close)
	servers[srv.URL] = srv
	return srv.URL, SPKIPin(srv.Certificate()), srv
}

// caPool writes the server's own certificate out as the CA to trust, so chain
// verification succeeds and the test is measuring the pin and nothing else.
func trustingClient(t *testing.T, url string, pins []string) (*Client, error) {
	t.Helper()
	// httptest's certificate is self-signed, so trusting it as a root is what
	// makes normal verification pass.
	dir := t.TempDir()
	caFile := dir + "/ca.pem"
	srvCert := pemFor(t, url)
	if err := writeFile(caFile, srvCert); err != nil {
		t.Fatal(err)
	}
	return New(Options{
		URL: url, User: "u", Password: "p",
		CAFile: caFile, CertPins: pins,
	})
}

func TestSPKIPinIsStableAndPrefixed(t *testing.T) {
	_, pin, srv := tlsManager(t)
	if !strings.HasPrefix(pin, PinPrefix) {
		t.Errorf("pin = %q, want the %q prefix", pin, PinPrefix)
	}
	// It must be the digest of the SubjectPublicKeyInfo, not of the whole
	// certificate: that is what lets the certificate rotate under a kept pin.
	sum := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	if want := PinPrefix + base64.StdEncoding.EncodeToString(sum[:]); pin != want {
		t.Errorf("pin = %q, want %q", pin, want)
	}
}

// The pin the agent prints is the pin the agent accepts. If those differ, the
// control is unusable no matter how sound the verification is.
func TestCorrectPinIsAccepted(t *testing.T) {
	url, pin, _ := tlsManager(t)
	c, err := trustingClient(t, url, []string{pin})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if res := c.Send(context.Background(), []map[string]any{{"a": 1}}); res.Err != nil {
		t.Errorf("a correctly pinned manager must be reachable: %v", res.Err)
	}
}

// The attack this exists for: a certificate that chains correctly, for a key
// the operator never pinned.
func TestWrongPinIsRefused(t *testing.T) {
	url, _, _ := tlsManager(t)
	other := sha256.Sum256([]byte("some other server's key"))
	c, err := trustingClient(t, url, []string{PinPrefix + base64.StdEncoding.EncodeToString(other[:])})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res := c.Send(context.Background(), []map[string]any{{"a": 1}})
	if res.Err == nil {
		t.Fatal("a manager whose key matches no pin must be refused even though its chain verifies")
	}
	if res.Delivered != 0 {
		t.Errorf("Delivered = %d, want 0", res.Delivered)
	}
}

// An operator told "does not match" and nothing else cannot act. The observed
// pin is the one string they need.
func TestMismatchReportsTheObservedPin(t *testing.T) {
	url, want, _ := tlsManager(t)
	var seen string
	dir := t.TempDir()
	caFile := dir + "/ca.pem"
	if err := writeFile(caFile, pemFor(t, url)); err != nil {
		t.Fatal(err)
	}
	other := sha256.Sum256([]byte("not it"))
	c, err := New(Options{
		URL: url, User: "u", Password: "p", CAFile: caFile,
		CertPins:   []string{hex.EncodeToString(other[:])},
		ObservePin: func(p string) { seen = p },
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Send(context.Background(), []map[string]any{{"a": 1}})
	if seen != want {
		t.Errorf("observed pin = %q, want the server's actual pin %q", seen, want)
	}
}

// Operators arrive with hex and with base64; refusing either is a papercut on a
// control that only works if people set it.
func TestPinAcceptsHexAndBase64AndPrefix(t *testing.T) {
	url, pin, srv := tlsManager(t)
	sum := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	for name, value := range map[string]string{
		"canonical": pin,
		"base64":    base64.StdEncoding.EncodeToString(sum[:]),
		"hex":       hex.EncodeToString(sum[:]),
		"hexPrefix": PinPrefix + hex.EncodeToString(sum[:]),
	} {
		c, err := trustingClient(t, url, []string{value})
		if err != nil {
			t.Errorf("%s: New: %v", name, err)
			continue
		}
		if res := c.Send(context.Background(), []map[string]any{{"a": 1}}); res.Err != nil {
			t.Errorf("%s form should be accepted: %v", name, res.Err)
		}
	}
}

// Several pins so a key can be rotated without an outage.
func TestAnyOfSeveralPinsMatches(t *testing.T) {
	url, pin, _ := tlsManager(t)
	stale := sha256.Sum256([]byte("last year's key"))
	c, err := trustingClient(t, url, []string{
		PinPrefix + base64.StdEncoding.EncodeToString(stale[:]), pin,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := c.Send(context.Background(), []map[string]any{{"a": 1}}); res.Err != nil {
		t.Errorf("one matching pin out of several is enough: %v", res.Err)
	}
}

func TestMalformedPinIsAStartupError(t *testing.T) {
	url, _, _ := tlsManager(t)
	for _, bad := range []string{"sha256/not-base64!!", "abcd", "sha256/" + strings.Repeat("a", 10)} {
		if _, err := trustingClient(t, url, []string{bad}); err == nil {
			t.Errorf("%q should be rejected at startup, not at the first delivery", bad)
		}
	}
}

// Pinning and "skip verification" together mean the operator has contradicted
// themselves, and guessing which half they meant is worse than asking.
func TestPinWithInsecureIsRefused(t *testing.T) {
	url, pin, _ := tlsManager(t)
	if _, err := New(Options{
		URL: url, User: "u", Password: "p", Insecure: true, CertPins: []string{pin},
	}); err == nil {
		t.Error("a pin together with --wazuh-insecure must be refused")
	}
}

// No pins configured must behave exactly as before, or adding the feature
// breaks every existing deployment.
func TestNoPinsKeepsNormalVerification(t *testing.T) {
	url, _, _ := tlsManager(t)
	c, err := trustingClient(t, url, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if res := c.Send(context.Background(), []map[string]any{{"a": 1}}); res.Err != nil {
		t.Errorf("with no pins a trusted manager must still work: %v", res.Err)
	}
}

// pemFor returns the httptest server's certificate in PEM form. The server is
// looked up from the registry the tests populate, keyed by URL.
func pemFor(t *testing.T, url string) []byte {
	t.Helper()
	srv := servers[url]
	if srv == nil {
		t.Fatalf("no server registered for %s", url)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

func writeFile(path string, body []byte) error { return os.WriteFile(path, body, 0o600) }

var servers = map[string]*httptest.Server{}
