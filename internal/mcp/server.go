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
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/cau-edr/cau/scanner"
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
	Sandbox   *Sandbox
	Info      ServerInfo
	RulesPath string // directory the ruleset was loaded from, for cau://rules
	SigDBPath string // signature DB path, for add_signature persistence
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
// out until in reaches EOF. It returns the first I/O error, or nil on a clean
// EOF. Protocol-level problems (bad JSON, unknown method) are reported back to
// the client as JSON-RPC errors, not returned from Serve.
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
			s.write(rpcResponse{JSONRPC: "2.0", Error: errf(codeParseError, "parse error: %v", jerr)})
			if err == io.EOF {
				return nil
			}
			continue
		}

		s.handle(&req)
		if err == io.EOF {
			return nil
		}
	}
}

// handle dispatches one request and writes its response (unless it is a
// notification).
func (s *Server) handle(req *rpcRequest) {
	result, rerr := s.dispatch(req)
	if req.isNotification() {
		return // notifications never get a response, even on error
	}
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	if rerr != nil {
		resp.Error = rerr
	} else {
		resp.Result = result
	}
	s.write(resp)
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

func (s *Server) write(resp rpcResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enc == nil {
		return
	}
	_ = s.enc.Encode(resp) // Encode appends a newline, giving us the framing
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
			"hashes, explain verdicts, test and draft YARA rules, and report ATT&CK " +
			"coverage. File access is confined to the configured scan roots; results " +
			"are bounded summaries, not raw dumps.",
	}, nil
}

// ── small helpers ────────────────────────────────────────────────────────────

func readLine(br *bufio.Reader) ([]byte, error) {
	line, err := br.ReadBytes('\n')
	return line, err
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
