// Package mcp implements the CAU engine's Model Context Protocol server: it
// exposes the scanner, the signature database, the YARA ruleset and the
// ATT&CK coverage matrix to an MCP client (an LLM agent or an IDE) as a set of
// tools, resources and prompts.
//
// The transport is JSON-RPC 2.0 over a line-delimited stream (the MCP stdio
// transport): one JSON message per line, no embedded newlines. A streamable
// HTTP transport is an intended follow-up; the protocol layer here is
// transport-agnostic (Serve takes an io.Reader / io.Writer) so adding it does
// not touch the tool handlers.
//
// Phase 3 non-negotiables are enforced here and in sandbox.go: results are
// bounded and summarized (never raw offset dumps), every file path is confined
// to a sandbox allowlist, and tool output is structured JSON.
package mcp

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/s-b-repo/cau/scanner"
	"github.com/s-b-repo/cau/scanner/static"
)

// ProtocolVersion is the MCP revision this server implements. When a client
// requests a different version the server still answers with this one; the
// client decides whether it can proceed.
const ProtocolVersion = "2025-06-18"

// JSON-RPC 2.0 error codes (a subset plus the ones this server raises).
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// maxRequestLine caps one stdio request line. The HTTP transport caps a
// request body at the same size (maxHTTPBody): MCP messages are small, so an
// over-cap line is rejected rather than buffered without bound.
const maxRequestLine = maxHTTPBody

// errLineTooLong reports a stdio request line over maxRequestLine. Serve
// answers it as a JSON-RPC protocol error and skips the rest of the line.
var errLineTooLong = errors.New("request line too long")

// ServerInfo identifies the server to the client.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Deps are the engine pieces a Server serves over MCP. Engine is required; the
// rest may be nil, in which case the tools that need them report a bounded
// error rather than panicking.
type Deps struct {
	Engine    *scanner.Engine
	Yara      *scanner.YaraScanner // engine.Yara, kept for rule enumeration/testing
	SigDB     *scanner.SignatureDB // engine.DB, kept for listing/adding signatures
	FuzzyDB   *static.FuzzyDB      // engine.FuzzyDB, for the coverage matrix's content counts
	Sandbox   *Sandbox
	Info      ServerInfo
	RulesPath string // directory the ruleset was loaded from, for cau://rules
	SigDBPath string // signature DB path, for add_signature persistence

	// The honesty index reads these. They are operator configuration (set on
	// the command line like --db and --rules), never client-supplied: the
	// honesty_index tool takes no path argument, so the sandbox stays the
	// only way a client reaches a file.
	ExpectPath   string            // coverage expectation file; "" = no baseline
	EvalPath     string            // evaluation report (cau eval run --out); "" = not measured
	ManifestPath string            // integrity baseline; "" = integrity.json next to SigDBPath
	PubKey       ed25519.PublicKey // key to verify the baseline's signature; nil = not checked
	// PubKeyErr is set when a key was supplied but could not be used, so the
	// index can say the signature was not checked and why.
	PubKeyErr string
}

// Server serves MCP requests over a line-delimited JSON-RPC transport.
type Server struct {
	deps Deps

	mu  sync.Mutex // serialises writes to the output stream
	enc *json.Encoder

	// callMu serialises request handling on the HTTP transport, where
	// requests would otherwise run concurrently. The engine's scan path is
	// per-call state, but the signature database's Add is not concurrency
	// safe, so one request is dispatched at a time. The stdio transport is
	// already serial and does not take it.
	callMu sync.Mutex

	initialized bool
}

// NewServer builds a server from its dependencies.
func NewServer(deps Deps) *Server {
	if deps.Info.Name == "" {
		deps.Info.Name = "cau-mcp"
	}
	return &Server{deps: deps}
}

// ── wire types ───────────────────────────────────────────────────────────────

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // absent for notifications
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func (e *rpcError) Error() string { return e.Message }

func errf(code int, format string, a ...interface{}) *rpcError {
	return &rpcError{Code: code, Message: fmt.Sprintf(format, a...)}
}

// isNotification reports whether the request carries no id (JSON-RPC
// notification: no response is sent).
func (r *rpcRequest) isNotification() bool { return len(r.ID) == 0 }

// ── serve loop ───────────────────────────────────────────────────────────────

// Serve reads line-delimited JSON-RPC requests from in and writes responses to
// out until in reaches EOF. It returns the first I/O error from either stream,
// or nil on a clean EOF. Protocol-level problems (bad JSON, unknown method, an
// over-long request line) are reported back to the client as JSON-RPC errors,
// not returned from Serve.
func (s *Server) Serve(in io.Reader, out io.Writer) error {
	s.enc = json.NewEncoder(out)
	s.enc.SetEscapeHTML(false)

	br := bufio.NewReaderSize(in, 1<<20)
	for {
		line, err := readLine(br)
		if err == io.EOF {
			if len(line) == 0 {
				return nil
			}
			// trailing line without newline: process then stop
		} else if err == errLineTooLong {
			// An over-long request is a protocol violation, not an I/O
			// failure. Drop the rest of the line so the next request stays
			// framed, answer the client, and keep serving — the same way the
			// HTTP transport answers an over-cap body.
			if derr := discardLine(br); derr != nil && derr != io.EOF {
				return derr
			}
			if werr := s.write(rpcResponse{JSONRPC: "2.0", Error: errf(codeInvalidRequest, "request line exceeds the %d-byte limit", maxRequestLine)}); werr != nil {
				return werr
			}
			continue
		} else if err != nil {
			return err
		}
		if len(trimSpace(line)) == 0 {
			if err == io.EOF {
				return nil
			}
			continue
		}

		var req rpcRequest
		if jerr := json.Unmarshal(line, &req); jerr != nil {
			if werr := s.write(rpcResponse{JSONRPC: "2.0", Error: errf(codeParseError, "parse error: %v", jerr)}); werr != nil {
				return werr
			}
			if err == io.EOF {
				return nil
			}
			continue
		}

		if werr := s.handle(&req); werr != nil {
			return werr
		}
		if err == io.EOF {
			return nil
		}
	}
}

// handle dispatches one request and writes its response (unless it is a
// notification). A write failure is returned so a broken output stream stops
// dispatch rather than silently swallowing a response the client never sees.
func (s *Server) handle(req *rpcRequest) error {
	result, rerr := s.dispatch(req)
	if req.isNotification() {
		return nil // notifications never get a response, even on error
	}
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	if rerr != nil {
		resp.Error = rerr
	} else {
		resp.Result = result
	}
	return s.write(resp)
}

// dispatch routes a method to its handler. It returns either a result or a
// JSON-RPC error.
func (s *Server) dispatch(req *rpcRequest) (interface{}, *rpcError) {
	switch req.Method {
	case "initialize":
		return s.onInitialize(req.Params)
	case "notifications/initialized", "initialized":
		s.initialized = true
		return nil, nil
	case "ping":
		return map[string]interface{}{}, nil
	case "tools/list":
		return s.onToolsList()
	case "tools/call":
		return s.onToolsCall(req.Params)
	case "resources/list":
		return s.onResourcesList()
	case "resources/templates/list":
		return s.onResourceTemplatesList()
	case "resources/read":
		return s.onResourcesRead(req.Params)
	case "prompts/list":
		return s.onPromptsList()
	case "prompts/get":
		return s.onPromptsGet(req.Params)
	default:
		return nil, errf(codeMethodNotFound, "method not found: %s", req.Method)
	}
}

// write encodes one response onto the output stream. The Encode error (a
// broken pipe on the client side, most commonly) is returned so Serve can stop
// dispatching requests whose responses can no longer reach the client.
func (s *Server) write(resp rpcResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enc == nil {
		return nil
	}
	// Encode appends a newline, giving us the framing
	return s.enc.Encode(resp)
}

// ── lifecycle ────────────────────────────────────────────────────────────────

type initializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    capabilities `json:"capabilities"`
	ServerInfo      ServerInfo   `json:"serverInfo"`
	Instructions    string       `json:"instructions,omitempty"`
}

type capabilities struct {
	Tools     *capFlag `json:"tools,omitempty"`
	Resources *capFlag `json:"resources,omitempty"`
	Prompts   *capFlag `json:"prompts,omitempty"`
}

type capFlag struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

func (s *Server) onInitialize(json.RawMessage) (interface{}, *rpcError) {
	return initializeResult{
		ProtocolVersion: ProtocolVersion,
		Capabilities: capabilities{
			Tools:     &capFlag{},
			Resources: &capFlag{},
			Prompts:   &capFlag{},
		},
		ServerInfo: s.deps.Info,
		Instructions: "CAU malware-detection engine. Tools scan files, directories and " +
			"hashes, explain verdicts, test and draft YARA rules, peel obfuscation " +
			"chains, inventory UEFI firmware images, boot chains and hardware identity, " +
			"summarise evaluation reports, and report ATT&CK coverage and the honesty " +
			"index. Every tool is read-only analysis: nothing here executes, quarantines, " +
			"blocks or kills. File access is confined to the configured scan roots; " +
			"results are bounded summaries, not raw dumps, and every cut is reported.",
	}, nil
}

// ── small helpers ────────────────────────────────────────────────────────────

// readLine returns the next line, including its newline delimiter. A line is
// capped at maxRequestLine, so a newline-free stream can never grow the
// accumulated line in proportion to the input: the loop bails out with
// errLineTooLong once the cap would be exceeded.
func readLine(br *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		frag, err := br.ReadSlice('\n')
		if len(line)+len(frag) > maxRequestLine {
			return nil, errLineTooLong
		}
		line = append(line, frag...)
		if err != bufio.ErrBufferFull {
			return line, err
		}
	}
}

// discardLine drops the remainder of an over-long request line so the next
// readLine starts at the following request's delimiter. It never accumulates
// the dropped bytes.
func discardLine(br *bufio.Reader) error {
	for {
		_, err := br.ReadSlice('\n')
		if err != bufio.ErrBufferFull {
			return err
		}
	}
}

func trimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && isSpace(b[i]) {
		i++
	}
	for j > i && isSpace(b[j-1]) {
		j--
	}
	return b[i:j]
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }
