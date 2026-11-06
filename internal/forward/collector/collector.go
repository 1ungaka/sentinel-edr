// Package collector delivers the SIEM sink formats (`cau scan --format ecs|cef|
// leef|gelf|syslog*|otlp`) to a collector over the network.
//
// The report package decides what an event says; this package only moves the
// bytes that reporter wrote, so what a collector receives is byte-identical
// to what `--format <fmt> --output file` writes locally. The destination URL
// picks the transport and the format picks the framing:
//
//	udp://host:port     one event per datagram
//	tcp://host:port     a stream; cleartext
//	tls://host:port     the same stream over TLS 1.2+ (RFC 5425 for syslog)
//	http(s)://host/path POST
//
// Stream framing per format:
//
//	syslog, syslog-*    RFC 6587 octet counting ("LEN SP FRAME")
//	gelf                NUL-terminated messages (the GELF TCP input)
//	ecs, cef, leef      newline-delimited
//
// HTTP bodies per format:
//
//	otlp                the ExportLogsServiceRequest, application/json
//	                    (POST to the collector's /v1/logs)
//	ecs + BulkIndex     an OpenSearch/Elasticsearch _bulk body: a create
//	                    action line before every document
//	gelf                one POST per message (the GELF HTTP input)
//	anything else       the events as newline-delimited lines
//
// Like the Wazuh forwarder this is in the free surface: one host talking to
// its own collector is a single-host action. And like it, nothing here ever
// fails a scan: a collector outage must not break a CI gate, so the caller
// logs the Result and keeps the scan's exit code.
package collector

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultTimeout bounds every connection attempt, write and HTTP request.
const DefaultTimeout = 10 * time.Second

// MaxDatagram is the largest event sent as one UDP datagram. It is the GELF
// UDP limit and comfortably under the 65,507-byte UDP payload ceiling; a
// larger event is reported as undeliverable rather than truncated, because a
// truncated finding is a wrong finding.
const MaxDatagram = 8192

// MaxBulkDocs bounds one _bulk request.
const MaxBulkDocs = 500

// Options configures a Client.
type Options struct {
	// URL is the destination: udp://, tcp://, tls://, http:// or https://.
	URL string
	// Format is the sink format the payload is in (a report.SinkFormats name).
	Format string
	// BulkIndex, with an http(s) URL and the ecs format, wraps the documents
	// as an OpenSearch/Elasticsearch _bulk body creating into this index or
	// data stream.
	BulkIndex string
	// Authorization, when set, is sent as the HTTP Authorization header. The
	// caller sources it from an environment variable, never from argv.
	Authorization string
	// CAFile trusts only this PEM bundle for TLS verification.
	CAFile string
	// Insecure disables TLS verification and permits http://. Opt-in.
	Insecure bool
	// Timeout is per connection, write and request; zero uses DefaultTimeout.
	Timeout time.Duration
}

// Client delivers one scan's sink payload.
type Client struct {
	opts    Options
	url     *url.URL
	tlsCfg  *tls.Config
	timeout time.Duration
	http    *http.Client
}

// Result reports what Send did. Attempted counts the events handed in and
// Delivered the ones written to the transport (for HTTP, accepted with a
// 2xx). UDP delivery is unacknowledged by nature: Delivered there means sent.
type Result struct {
	Attempted int
	Delivered int
	Err       error
}

var streamFormats = map[string]bool{
	"ecs": true, "cef": true, "leef": true, "gelf": true,
	"syslog": true, "syslog-ecs": true, "syslog-cef": true, "syslog-leef": true,
}

// New validates the options, so a typo at the command line is an error and
// not a silent no-op.
func New(opts Options) (*Client, error) {
	if strings.TrimSpace(opts.URL) == "" {
		return nil, errors.New("collector: a destination URL is required")
	}
	u, err := url.Parse(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("collector: parse url: %w", err)
	}
	format := strings.ToLower(strings.TrimSpace(opts.Format))
	opts.Format = format
	c := &Client{opts: opts, url: u, timeout: opts.Timeout}
	if c.timeout <= 0 {
		c.timeout = DefaultTimeout
	}

	switch u.Scheme {
	case "udp", "tcp", "tls":
		if u.Port() == "" || u.Hostname() == "" {
			return nil, fmt.Errorf("collector: %s:// needs host:port (got %q)", u.Scheme, u.Host)
		}
		if !streamFormats[format] {
			return nil, fmt.Errorf("collector: format %q cannot be sent over %s:// (otlp is HTTP-only; text, json, sarif and ocsf are reports, not sink formats)", format, u.Scheme)
		}
		if opts.BulkIndex != "" {
			return nil, errors.New("collector: a bulk index applies to http(s):// destinations only")
		}
		if opts.Authorization != "" {
			return nil, errors.New("collector: an Authorization header applies to http(s):// destinations only")
		}
	case "http", "https":
		if u.Host == "" {
			return nil, errors.New("collector: http(s):// needs a host")
		}
		if u.Scheme == "http" && !opts.Insecure {
			return nil, errors.New("collector: refusing http:// without the insecure opt-in (findings and credentials would travel in cleartext)")
		}
		if !streamFormats[format] && format != "otlp" {
			return nil, fmt.Errorf("collector: format %q is not a sink format", format)
		}
		if opts.BulkIndex != "" && format != "ecs" {
			return nil, fmt.Errorf("collector: a bulk index needs the ecs format (got %q)", format)
		}
		if strings.ContainsAny(opts.BulkIndex, "\r\n\"\\ ") {
			return nil, errors.New("collector: bulk index name contains characters an index name cannot hold")
		}
	default:
		return nil, fmt.Errorf("collector: url scheme must be udp, tcp, tls, http or https (got %q)", u.Scheme)
	}

	if u.Scheme == "tls" || u.Scheme == "https" || u.Scheme == "http" {
		c.tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
		if opts.Insecure {
			c.tlsCfg.InsecureSkipVerify = true // explicit opt-in flag
		} else if opts.CAFile != "" {
			pem, rerr := os.ReadFile(opts.CAFile)
			if rerr != nil {
				return nil, fmt.Errorf("collector: read CA bundle %s: %w", opts.CAFile, rerr)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("collector: CA bundle %s contained no usable certificates", opts.CAFile)
			}
			c.tlsCfg.RootCAs = pool
		}
	}
	if u.Scheme == "http" || u.Scheme == "https" {
		httpTLS := c.tlsCfg.Clone()
		httpTLS.ServerName = "" // net/http derives it per request
		c.http = &http.Client{
			Timeout:   c.timeout,
			Transport: &http.Transport{TLSClientConfig: httpTLS},
			// A redirect could carry findings to a host the operator never
			// named; a collector endpoint does not redirect.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return c, nil
}

// Cleartext reports whether the destination carries findings unencrypted, so
// the caller can say so once on its status line.
func (c *Client) Cleartext() bool {
	return c.url.Scheme == "udp" || c.url.Scheme == "tcp" || c.url.Scheme == "http"
}

// Budget is the overall time a caller should allow one Send: enough for a
// handful of sequential requests, bounded so a dead collector cannot hold a
// finished scan open indefinitely.
func (c *Client) Budget() time.Duration { return 5*c.timeout + 10*time.Second }

// Events splits a sink payload into its events: the single document for otlp
// (count is the number of log records it holds), otherwise one per line.
func Events(format string, payload []byte) (events [][]byte, count int) {
	if strings.EqualFold(format, "otlp") {
		n := otlpRecords(payload)
		if n == 0 {
			return nil, 0
		}
		return [][]byte{bytes.TrimRight(payload, "\n")}, n
	}
	for _, line := range bytes.Split(payload, []byte{'\n'}) {
		if len(line) > 0 {
			events = append(events, line)
		}
	}
	return events, len(events)
}

func otlpRecords(payload []byte) int {
	var doc struct {
		ResourceLogs []struct {
			ScopeLogs []struct {
				LogRecords []json.RawMessage `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if json.Unmarshal(payload, &doc) != nil {
		return 0
	}
	n := 0
	for _, rl := range doc.ResourceLogs {
		for _, sl := range rl.ScopeLogs {
			n += len(sl.LogRecords)
		}
	}
	return n
}

// Send delivers the payload a sink reporter wrote. An empty payload is a
// successful no-op: no connection is opened for a clean scan.
func (c *Client) Send(ctx context.Context, payload []byte) Result {
	events, count := Events(c.opts.Format, payload)
	r := Result{Attempted: count}
	if count == 0 {
		return r
	}
	switch c.url.Scheme {
	case "udp":
		r.Delivered, r.Err = c.sendUDP(ctx, events)
	case "tcp", "tls":
		r.Delivered, r.Err = c.sendStream(ctx, events)
	default:
		r.Delivered, r.Err = c.sendHTTP(ctx, events, count)
	}
	return r
}

func (c *Client) deadline(ctx context.Context) time.Time {
	d := time.Now().Add(c.timeout)
	if cd, ok := ctx.Deadline(); ok && cd.Before(d) {
		return cd
	}
	return d
}

func (c *Client) sendUDP(ctx context.Context, events [][]byte) (int, error) {
	var d net.Dialer
	d.Timeout = c.timeout
	conn, err := d.DialContext(ctx, "udp", c.url.Host)
	if err != nil {
		return 0, fmt.Errorf("collector: dial %s: %w", c.url.Host, err)
	}
	defer conn.Close()
	sent := 0
	var firstErr error
	for _, ev := range events {
		if len(ev) > MaxDatagram {
			if firstErr == nil {
				firstErr = fmt.Errorf("collector: a %d-byte event exceeds the %d-byte datagram limit; use tcp:// or tls://", len(ev), MaxDatagram)
			}
			continue
		}
		_ = conn.SetWriteDeadline(c.deadline(ctx))
		if _, err := conn.Write(ev); err != nil {
			return sent, fmt.Errorf("collector: send to %s: %w", c.url.Host, err)
		}
		sent++
	}
	return sent, firstErr
}

// frame applies the stream framing for the client's format.
func (c *Client) frame(ev []byte) []byte {
	switch {
	case strings.HasPrefix(c.opts.Format, "syslog"):
		// RFC 6587 section 3.4.1 octet counting: MSG-LEN SP SYSLOG-MSG. It is
		// the only framing RFC 5425 (syslog over TLS) allows, and unlike
		// newline framing it cannot be confused by message content.
		out := make([]byte, 0, len(ev)+8)
		out = strconv.AppendInt(out, int64(len(ev)), 10)
		out = append(out, ' ')
		return append(out, ev...)
	case c.opts.Format == "gelf":
		return append(append(make([]byte, 0, len(ev)+1), ev...), 0)
	default:
		return append(append(make([]byte, 0, len(ev)+1), ev...), '\n')
	}
}

func (c *Client) sendStream(ctx context.Context, events [][]byte) (int, error) {
	d := &net.Dialer{Timeout: c.timeout}
	var conn net.Conn
	var err error
	if c.url.Scheme == "tls" {
		conn, err = (&tls.Dialer{NetDialer: d, Config: c.tlsCfg}).DialContext(ctx, "tcp", c.url.Host)
	} else {
		conn, err = d.DialContext(ctx, "tcp", c.url.Host)
	}
	if err != nil {
		return 0, fmt.Errorf("collector: dial %s: %w", c.url.Host, err)
	}
	defer conn.Close()
	sent := 0
	for _, ev := range events {
		_ = conn.SetWriteDeadline(c.deadline(ctx))
		if _, err := conn.Write(c.frame(ev)); err != nil {
			return sent, fmt.Errorf("collector: send to %s: %w", c.url.Host, err)
		}
		sent++
	}
	return sent, nil
}

func (c *Client) sendHTTP(ctx context.Context, events [][]byte, count int) (int, error) {
	switch {
	case c.opts.Format == "otlp":
		if err := c.post(ctx, "application/json", events[0]); err != nil {
			return 0, err
		}
		return count, nil
	case c.opts.Format == "gelf":
		// The GELF HTTP input accepts exactly one message per request.
		for i, ev := range events {
			if err := c.post(ctx, "application/json", ev); err != nil {
				return i, err
			}
		}
		return len(events), nil
	case c.opts.BulkIndex != "":
		action, err := json.Marshal(map[string]any{"create": map[string]any{"_index": c.opts.BulkIndex}})
		if err != nil {
			return 0, fmt.Errorf("collector: encode bulk action: %w", err)
		}
		done := 0
		for start := 0; start < len(events); start += MaxBulkDocs {
			end := min(start+MaxBulkDocs, len(events))
			var body bytes.Buffer
			for _, ev := range events[start:end] {
				body.Write(action)
				body.WriteByte('\n')
				body.Write(ev)
				body.WriteByte('\n')
			}
			if err := c.postBulk(ctx, body.Bytes()); err != nil {
				return done, err
			}
			done = end
		}
		return done, nil
	default:
		ctype := "text/plain; charset=utf-8"
		if c.opts.Format == "ecs" || c.opts.Format == "syslog-ecs" {
			ctype = "application/x-ndjson"
		}
		body := append(bytes.Join(events, []byte{'\n'}), '\n')
		if err := c.post(ctx, ctype, body); err != nil {
			return 0, err
		}
		return len(events), nil
	}
}

func (c *Client) do(ctx context.Context, ctype string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("collector: build request: %w", err)
	}
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", "cau-collector")
	if c.opts.Authorization != "" {
		req.Header.Set("Authorization", c.opts.Authorization)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("collector: post: %w", scrub(err, c.opts.Authorization))
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("collector: post: %s (%s)", resp.Status, snippet(respBody))
	}
	return respBody, nil
}

func (c *Client) post(ctx context.Context, ctype string, body []byte) error {
	_, err := c.do(ctx, ctype, body)
	return err
}

// postBulk posts a _bulk body and reads the response: the bulk API answers
// 200 even when individual documents were rejected, with "errors": true.
func (c *Client) postBulk(ctx context.Context, body []byte) error {
	resp, err := c.do(ctx, "application/x-ndjson", body)
	if err != nil {
		return err
	}
	var out struct {
		Errors bool `json:"errors"`
	}
	if json.Unmarshal(resp, &out) == nil && out.Errors {
		return fmt.Errorf("collector: bulk request accepted but some documents were rejected (%s)", snippet(resp))
	}
	return nil
}

// scrub removes a credential from an error string, in case a transport error
// ever echoes a header.
func scrub(err error, secret string) error {
	if secret == "" || !strings.Contains(err.Error(), secret) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), secret, "[redacted]"))
}

// snippet keeps a short, single-line, control-free slice of a response body
// for a log line, so a collector's reply cannot rewrite the terminal.
func snippet(b []byte) string {
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
		s = s[:200] + "..."
	}
	return s
}
