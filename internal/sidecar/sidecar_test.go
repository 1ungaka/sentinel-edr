package sidecar

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The client and the sidecar speak the same protocol: a request goes in, a
// response comes out.
func TestClientScoresThroughTheSidecar(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "sidecar.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		_ = Serve(l, func(req Request) Response {
			if req.Model != "embedder@1.0.0" {
				return Response{Error: "no such model"}
			}
			return Response{
				OK:      true,
				Model:   req.Model,
				Scores:  map[string]float64{"malicious": 0.91},
				Labels:  map[string]string{"malicious": "malware"},
				Version: "test",
			}
		})
	}()

	c := &Client{Socket: sock, Timeout: 5 * time.Second}
	resp, err := c.Score(Request{Model: "embedder@1.0.0", ModelBytes: []byte("bytes")})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.OK {
		t.Fatal("the response is not ok")
	}
	if resp.Scores["malicious"] != 0.91 {
		t.Errorf("scores = %v", resp.Scores)
	}
	if resp.Labels["malicious"] != "malware" {
		t.Errorf("labels = %v", resp.Labels)
	}
}

// A model that did not run is an error, and the sidecar's reason comes with
// it: a sidecar that says "no" must not be read as "clean".
func TestClientReportsAModelThatDidNotRun(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "sidecar.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		_ = Serve(l, func(Request) Response {
			return Response{Error: "the model failed to load"}
		})
	}()

	c := &Client{Socket: sock, Timeout: 5 * time.Second}
	resp, err := c.Score(Request{Model: "embedder@1.0.0"})
	if err == nil {
		t.Fatal("a model that did not run was reported as a score")
	}
	if !strings.Contains(err.Error(), "failed to load") {
		t.Errorf("the reason was lost: %v", err)
	}
	if resp != nil && resp.OK {
		t.Error("the response claims ok")
	}
}

// A sidecar that is not there is an error, not a silent clean.
func TestClientReportsAMissingSidecar(t *testing.T) {
	c := &Client{Socket: filepath.Join(t.TempDir(), "absent.sock"), Timeout: time.Second}
	if _, err := c.Score(Request{Model: "m"}); err == nil {
		t.Fatal("a missing sidecar was not reported")
	}
}

// A frame that claims more than the limit is refused before anything is
// allocated for it.
func TestReadFrameRefusesAnOversizedFrame(t *testing.T) {
	frame := []byte{0xff, 0xff, 0xff, 0xff}
	var resp Response
	if err := ReadFrame(strings.NewReader(string(frame)), &resp); err == nil {
		t.Fatal("an oversized frame was accepted")
	}
}

// The request and the response are JSON with the documented field names: the
// sidecar is another program, and the contract is the wire format.
func TestTheFrameFormatIsJSON(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "sidecar.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var got Request
	go func() {
		_ = Serve(l, func(req Request) Response {
			got = req
			return Response{OK: true}
		})
	}()
	c := &Client{Socket: sock, Timeout: 5 * time.Second}
	if _, err := c.Score(Request{Model: "m@1", ModelBytes: []byte("x"), Options: map[string]any{"threshold": 0.5}}); err != nil {
		t.Fatal(err)
	}
	if got.Model != "m@1" {
		t.Errorf("the model did not arrive: %+v", got)
	}
	if string(got.ModelBytes) != "x" {
		t.Errorf("the bytes did not arrive: %q", got.ModelBytes)
	}
	if got.Options["threshold"] != 0.5 {
		t.Errorf("the options did not arrive: %v", got.Options)
	}
}

// A client that connects and never sends a frame must not cost a goroutine
// and a file descriptor for ever, and must not stop the sidecar serving the
// clients that do send one.
func TestAClientThatNeverSpeaksDoesNotStopTheSidecar(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "sidecar.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		_ = Serve(l, func(Request) Response { return Response{OK: true} })
	}()

	// A client that says nothing at all.
	silent, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()

	// The sidecar still answers the clients that do speak.
	c := &Client{Socket: sock, Timeout: 5 * time.Second}
	if _, err := c.Score(Request{Model: "m@1"}); err != nil {
		t.Fatalf("the sidecar stopped serving: %v", err)
	}
}

var _ net.Listener = (net.Listener)(nil)
