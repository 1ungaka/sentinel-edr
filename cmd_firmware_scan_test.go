package main

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/internal/report"
)

// firmwareFixture writes an image with a gzip member inside it.
func firmwareFixture(t *testing.T, payload string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	path := filepath.Join(t.TempDir(), "firmware.bin")
	image := append([]byte("FIRMWARE HEADER PADDING"), buf.Bytes()...)
	if err := os.WriteFile(path, image, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// The scan looks inside the image and reports the container it found.
func TestFirmwareScanFindsTheContainer(t *testing.T) {
	path := firmwareFixture(t, "payload bytes")
	code, out, errOut := runCLI(t, "firmware", "scan", "--rules", "rules", path)
	if code != report.ExitOK {
		t.Fatalf("code=%d stderr=%s\n%s", code, errOut, out)
	}
	if !strings.Contains(out, "gzip") {
		t.Errorf("the container was not reported:\n%s", out)
	}
	if !strings.Contains(out, "opened") {
		t.Errorf("the container was not opened:\n%s", out)
	}
	if !strings.Contains(out, "members:") {
		t.Errorf("the members were not reported:\n%s", out)
	}
}

// A member that trips a rule is reported, and the run can fail on it.
func TestFirmwareScanReportsARuleHit(t *testing.T) {
	// The payload carries the strings the bundled wannacry rule looks for
	// ("3 of them").
	path := firmwareFixture(t, "WNcry@2017 WanaCryptor WanaCrypt0r tasksche.exe")
	code, out, errOut := runCLI(t, "firmware", "scan", "--rules", "rules", "--fail-on", "malicious", path)
	if code != report.ExitThreat {
		t.Fatalf("code=%d stderr=%s\n%s", code, errOut, out)
	}
	if !strings.Contains(out, "wannacry") {
		t.Errorf("the rule hit was not reported:\n%s", out)
	}
}

// The JSON form carries the containers and the members.
func TestFirmwareScanJSON(t *testing.T) {
	path := firmwareFixture(t, "payload bytes")
	code, out, errOut := runCLI(t, "firmware", "scan", "--rules", "rules", "--format", "json", path)
	if code != report.ExitOK {
		t.Fatalf("code=%d stderr=%s", code, errOut)
	}
	if !strings.Contains(out, "\"containers\"") || !strings.Contains(out, "\"members\"") {
		t.Errorf("the JSON does not carry the scan:\n%s", out)
	}
}

// The plain `cau firmware <image>` form still parses an image.
func TestFirmwareParseStillWorks(t *testing.T) {
	path := firmwareFixture(t, "payload bytes")
	code, _, errOut := runCLI(t, "firmware", path)
	if code == report.ExitUsage {
		t.Fatalf("the plain form became a usage error: %s", errOut)
	}
}
