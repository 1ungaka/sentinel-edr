// Package sidecar talks to the inference sidecar.
//
// The engine never does inference. A model is a file, running it is another
// process's job, and the two must not be confused: the core reads files,
// hashes them and matches rules, and it never loads a model into its own
// address space. A model that the core can be made to execute is a model that
// can execute in the core.
//
// The sidecar is a separate process that holds the runtime (ONNX Runtime and
// its model artifacts) and answers one question: what does this model say
// about these bytes? The protocol is deliberately small — one JSON request,
// one JSON response — and the transport is a length-prefixed frame over a
// unix socket, so the core needs no dependency of its own to speak it.
//
// The production deployment of the sidecar is an ONNX Runtime service; this
// package is the engine's half of that conversation, and the protocol is
// documented here so both halves can be written against it.
package sidecar

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// MaxFrameBytes bounds one protocol frame. A frame is a request or a
// response, and both are small; the bound is what keeps a hostile or broken
// sidecar from making the core allocate without limit.
const MaxFrameBytes = 8 << 20

// Request asks the sidecar to score bytes with a model.
//
// The model is named by the registry's identity (name@version), not by path:
// which artifact may run is the registry's decision, and the sidecar holds the
// artifacts. ModelBytes carries the bytes to score, base64-encoded, because
// the frame is JSON and a model input is usually a file.
type Request struct {
	// Model is the registry identity of the model ("embedder@1.2.0").
	Model string `json:"model"`
	// ModelBytes is the input, base64-encoded.
	ModelBytes []byte `json:"bytes"`
	// Options are the model's own knobs, passed through as they are.
	Options map[string]any `json:"options,omitempty"`
}

// Response is the sidecar's answer.
type Response struct {
	// OK says whether the model ran.
	OK bool `json:"ok"`
	// Scores are the model's output: whatever the model produces, as numbers.
	Scores map[string]float64 `json:"scores,omitempty"`
	// Labels are the model's own labels for the scores.
	Labels map[string]string `json:"labels,omitempty"`
	// Model is the identity the sidecar says it ran.
	Model string `json:"model,omitempty"`
	// Version is the sidecar's own version, so a report says what answered.
	Version string `json:"version,omitempty"`
	// Error says why the model did not run.
	Error string `json:"error,omitempty"`
	// Duration is how long the model took, as the sidecar measured it.
	DurationMS int64 `json:"duration_ms,omitempty"`
}

// Client talks to one sidecar over a unix socket.
type Client struct {
	// Socket is the sidecar's unix socket path.
	Socket string
	// Timeout bounds one request. A sidecar that stops answering must not
	// hold the scan for ever.
	Timeout time.Duration
}

// DefaultTimeout is the request timeout the client uses when none is set.
const DefaultTimeout = 30 * time.Second

// Score asks the sidecar to score bytes with a model.
func (c *Client) Score(req Request) (*Response, error) {
	if c.Socket == "" {
		return nil, fmt.Errorf("sidecar: no socket configured")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	deadline := time.Now().Add(timeout)

	conn, err := net.DialTimeout("unix", c.Socket, timeout)
	if err != nil {
		return nil, fmt.Errorf("sidecar: cannot reach %s: %w", c.Socket, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("sidecar: set deadline: %w", err)
	}

	if err := WriteFrame(conn, req); err != nil {
		return nil, err
	}
	var resp Response
	if err := ReadFrame(conn, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		if resp.Error == "" {
			return &resp, fmt.Errorf("sidecar: the model did not run")
		}
		return &resp, fmt.Errorf("sidecar: %s", resp.Error)
	}
	return &resp, nil
}

// WriteFrame writes one length-prefixed JSON frame.
func WriteFrame(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("sidecar: render: %w", err)
	}
	if len(data) > MaxFrameBytes {
		return fmt.Errorf("sidecar: the frame is %d bytes, over the %d byte limit", len(data), MaxFrameBytes)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("sidecar: write: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("sidecar: write: %w", err)
	}
	return nil
}

// ReadFrame reads one length-prefixed JSON frame.
func ReadFrame(r io.Reader, v any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return fmt.Errorf("sidecar: read the frame header: %w", err)
	}
	n := binary.BigEndian.Uint32(header[:])
	if n > MaxFrameBytes {
		return fmt.Errorf("sidecar: the frame claims %d bytes, over the %d byte limit", n, MaxFrameBytes)
	}
	data := make([]byte, n) // audit:ok bounded: n was checked against MaxFrameBytes on the line above
	if _, err := io.ReadFull(r, data); err != nil {
		return fmt.Errorf("sidecar: read the frame: %w", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("sidecar: parse the frame: %w", err)
	}
	return nil
}

// Serve answers requests on a listener with the given handler. It is what a
// sidecar (or a test double of one) does.
func Serve(l net.Listener, handle func(Request) Response) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			var req Request
			if err := ReadFrame(c, &req); err != nil {
				return
			}
			_ = WriteFrame(c, handle(req))
		}(conn)
	}
}

// Listen opens the socket a sidecar listens on.
func Listen(path string) (net.Listener, error) {
	// A socket left behind by a sidecar that died would make the next one
	// fail to bind, so it is removed first. A socket that cannot be removed
	// is a real problem, not a detail: the sidecar would not be able to
	// listen at all.
	if _, err := os.Stat(path); err == nil {
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("sidecar: the socket left at %s cannot be removed: %w", path, err)
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("sidecar: listen on %s: %w", path, err)
	}
	return l, nil
}
