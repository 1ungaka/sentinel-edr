// Package wazuh ships CAU findings to a Wazuh Manager over its REST API.
//
// The Wazuh Manager (default :55000) authenticates with HTTP Basic against
// `/security/user/authenticate`, which returns a short-lived JWT; events are
// then POSTed to `/events` with `Authorization: Bearer <token>` and a body of
// the shape `{"events":["<json-event-1>", ...]}`. The payload we send is the
// same OCSF Detection Findings document `cau scan --format ocsf` writes
// locally, one finding per element of `events[]`, so a Wazuh custom decoder
// has the schema version and class_uid it needs.
//
// This package is in the free surface of the engine on purpose: the licensing
// mechanics are "paid is only what a single host cannot do alone" (see
// PLAN.md and docs/pricing.md). An on-host agent speaking directly to a
// Wazuh manager is a single-host action, so it ships free, and the engine
// never routes it through the console.
//
// Nothing here fails the scan on a transport error: a Wazuh outage must not
// break CI. The caller logs the forward's result and keeps the scan's exit
// code.
package wazuh

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// DefaultTimeout bounds every single request (authenticate or send). The
// forward is invoked after the scan has finished and writes nothing back to
// the report, so a slow Wazuh instance only slows the trailing status line.
const DefaultTimeout = 10 * time.Second

// MaxEventsPerRequest bounds one `/events` POST so a very large scan never
// hands the manager a megabyte-per-finding blob. Multiple requests are made
// in sequence and the last error (if any) is returned.
const MaxEventsPerRequest = 100

// Options configures a Client. URL is the Wazuh Manager API base (e.g.
// https://wazuh.example.com:55000); User + Password authenticate against
// that API; CAFile, when set, trusts only that PEM bundle for TLS
// verification; Insecure disables TLS verification entirely and must be
// opt-in. Timeout is per request; a zero value uses DefaultTimeout.
type Options struct {
	URL      string
	User     string
	Password string
	CAFile   string
	Insecure bool
	Timeout  time.Duration
}

// Client holds the resolved HTTP transport and a parsed base URL.
type Client struct {
	base *url.URL
	http *http.Client
	user string
	pass string
}

// New builds a Client, validating the options enough that a typo at the CLI
// surfaces as an error rather than a silent no-op. The password is kept in
// the Client (never logged); the caller is expected to source it from an
// environment variable, since argv is world-readable in /proc/<pid>/cmdline.
func New(opts Options) (*Client, error) {
	if strings.TrimSpace(opts.URL) == "" {
		return nil, errors.New("wazuh: --wazuh-url is required")
	}
	base, err := url.Parse(strings.TrimRight(opts.URL, "/"))
	if err != nil {
		return nil, fmt.Errorf("wazuh: parse url: %w", err)
	}
	if base.Scheme != "https" && base.Scheme != "http" {
		return nil, fmt.Errorf("wazuh: url scheme must be http or https (got %q)", base.Scheme)
	}
	if base.Scheme == "http" && !opts.Insecure {
		// A plain-HTTP URL is almost always a misconfiguration: the Wazuh
		// Manager API is https-only out of the box. Reject it unless the
		// operator explicitly asks for the loose TLS setting too, which
		// doubles as the "yes, I know this is not encrypted" acknowledgement.
		return nil, fmt.Errorf("wazuh: refusing http:// without --wazuh-insecure (plaintext credentials)")
	}
	if strings.TrimSpace(opts.User) == "" {
		return nil, errors.New("wazuh: --wazuh-user is required")
	}
	if strings.TrimSpace(opts.Password) == "" {
		return nil, errors.New("wazuh: password empty; pass it via --wazuh-password-env <VAR>")
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.Insecure {
		tlsCfg.InsecureSkipVerify = true // explicit opt-in flag; fail-visible on the banner
	} else if opts.CAFile != "" {
		pem, rerr := os.ReadFile(opts.CAFile)
		if rerr != nil {
			return nil, fmt.Errorf("wazuh: read CA bundle %s: %w", opts.CAFile, rerr)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("wazuh: CA bundle %s contained no usable certificates", opts.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{
		base: base,
		http: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
		user: opts.User,
		pass: opts.Password,
	}, nil
}

// Result reports what a Send call did. Attempted counts the events the
// caller handed in; Delivered counts the ones the Manager accepted (a 2xx on
// the batch). One failed batch stops the walk — the first error is kept and
// the remaining events are left as Attempted-but-not-Delivered.
type Result struct {
	Attempted int
	Delivered int
	Err       error
}

// Send POSTs each OCSF finding as one Wazuh event. Each finding is encoded
// as a single JSON string (the shape `/events` expects); the Manager side
// then applies its usual decoders / rulebase on them. A JSON array document
// written by the OCSF reporter is the canonical input to this function.
func (c *Client) Send(ctx context.Context, findings []map[string]any) Result {
	r := Result{Attempted: len(findings)}
	if len(findings) == 0 {
		return r
	}
	token, err := c.authenticate(ctx)
	if err != nil {
		r.Err = err
		return r
	}
	for start := 0; start < len(findings); start += MaxEventsPerRequest {
		end := start + MaxEventsPerRequest
		if end > len(findings) {
			end = len(findings)
		}
		if err := c.postBatch(ctx, token, findings[start:end]); err != nil {
			r.Err = err
			return r
		}
		r.Delivered += end - start
	}
	return r
}

// authenticate exchanges user/pass for a short-lived JWT.
func (c *Client) authenticate(ctx context.Context) (string, error) {
	u := *c.base
	u.Path = u.Path + "/security/user/authenticate"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("wazuh: build auth request: %w", err)
	}
	// Explicit Basic header rather than URL userinfo so no credential leaks
	// into a redirect Location (http.Client strips Authorization on a
	// cross-origin redirect, which is the safe default).
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.user+":"+c.pass)))
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("wazuh: authenticate: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("wazuh: authenticate: %s (%s)", resp.Status, trimSnippet(body))
	}
	var env struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return "", fmt.Errorf("wazuh: parse auth response: %w", err)
	}
	if env.Data.Token == "" {
		return "", errors.New("wazuh: authenticate returned an empty token")
	}
	return env.Data.Token, nil
}

// postBatch encodes a slice of OCSF findings as JSON strings, wraps them in
// the `{"events":[...]}` envelope and POSTs to /events.
func (c *Client) postBatch(ctx context.Context, token string, findings []map[string]any) error {
	events := make([]string, 0, len(findings))
	for _, f := range findings {
		b, err := json.Marshal(f)
		if err != nil {
			return fmt.Errorf("wazuh: encode finding: %w", err)
		}
		events = append(events, string(b))
	}
	envelope, err := json.Marshal(map[string]any{"events": events})
	if err != nil {
		return fmt.Errorf("wazuh: encode envelope: %w", err)
	}
	u := *c.base
	u.Path = u.Path + "/events"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(envelope))
	if err != nil {
		return fmt.Errorf("wazuh: build events request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("wazuh: send events: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("wazuh: send events: %s (%s)", resp.Status, trimSnippet(body))
	}
	return nil
}

// trimSnippet keeps a small slice of an error body for a log line, with
// newlines and tabs collapsed so a response doesn't rewrite the terminal.
func trimSnippet(b []byte) string {
	s := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, string(b))
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
