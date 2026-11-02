package mcp

import (
	"encoding/json"
	"io"
	"net/http"
)

// HTTP transport (the MCP "streamable HTTP" transport, JSON subset).
//
// A single endpoint accepts a JSON-RPC message by POST and returns the
// JSON-RPC response as application/json. The full streamable-HTTP transport
// also allows a server to stream notifications back over Server-Sent Events;
// this server never sends unsolicited messages, so the JSON response subset is
// a complete and conformant implementation for it. GET (the SSE channel) is
// therefore answered with 405.
//
// Requests are dispatched one at a time (callMu): the stdio transport is
// inherently serial, and the signature database's Add is not concurrency safe,
// so the HTTP transport matches that contract rather than racing it.

// maxHTTPBody caps a single request body. MCP messages are small; a scan reads
// files from disk, not from the request body.
const maxHTTPBody = 4 << 20 // 4 MiB

// HTTPHandler returns an http.Handler that serves the MCP endpoint. Mount it
// at the path of your choice (the handler itself does not route on path, so a
// single endpoint like /mcp is typical).
func (s *Server) HTTPHandler() http.Handler {
	return http.HandlerFunc(s.serveHTTP)
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handleHTTPPost(w, r)
	case http.MethodDelete:
		// Session termination. This server keeps no session state, so there is
		// nothing to tear down.
		w.WriteHeader(http.StatusNoContent)
	case http.MethodGet:
		// The optional server->client SSE stream. Unused: the server sends no
		// unsolicited messages.
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "this server streams no server-initiated messages; use POST", http.StatusMethodNotAllowed)
	default:
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleHTTPPost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxHTTPBody))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, rpcResponse{
			JSONRPC: "2.0", Error: errf(codeParseError, "reading request body: %v", err),
		})
		return
	}

	var req rpcRequest
	if jerr := json.Unmarshal(body, &req); jerr != nil {
		writeJSON(w, http.StatusBadRequest, rpcResponse{
			JSONRPC: "2.0", Error: errf(codeParseError, "parse error: %v", jerr),
		})
		return
	}

	s.callMu.Lock()
	result, rerr := s.dispatch(&req)
	s.callMu.Unlock()

	// A notification (no id) expects no response body.
	if req.isNotification() {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	if rerr != nil {
		resp.Error = rerr
	} else {
		resp.Result = result
	}
	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
