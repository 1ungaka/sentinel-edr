package linuxpkg

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"io"
	"strings"
)

// Generic archives (.zip, .tar and the gzip/bzip2 tar variants) are a common
// delivery wrapper for a payload plus an install/setup script — "unzip, then run
// ./install.sh". We do not treat an archive as a package, but we do pull out the
// scripts it carries (anything with a shell shebang, or named like an installer)
// and run the shared vectors over them, so a curl|bash in a bundled setup.sh is
// caught whether it arrives loose or zipped.

var magicZip = []byte("PK\x03\x04")

func isZip(data []byte) bool { return bytes.HasPrefix(data, magicZip) }

// isPlainTar reports whether data is an uncompressed tar that is NOT one of the
// package tars handled earlier (arch/docker). It confirms by reading one valid
// header rather than trusting the ustar magic alone.
func isPlainTar(data []byte) bool {
	if len(data) < 512 {
		return false
	}
	// ustar magic sits at offset 257.
	if !bytes.HasPrefix(data[257:], []byte("ustar")) {
		return false
	}
	_, err := tar.NewReader(bytes.NewReader(data)).Next()
	return err == nil
}

// isGenericArchive matches .zip and (compressed) tar wrappers that were not
// already claimed by a more specific package format.
func isGenericArchive(data []byte) bool {
	if isZip(data) {
		return true
	}
	if bytes.HasPrefix(data, magicGzip) || bytes.HasPrefix(data, magicBzip2) {
		body, _ := decompressAny(data)
		return body != nil && isPlainTar(body)
	}
	return isPlainTar(data)
}

// looksLikeInstaller reports whether a member name is a bundled install/setup
// script worth scanning.
func looksLikeInstaller(name string) bool {
	base := strings.ToLower(name[strings.LastIndexByte(name, '/')+1:])
	if strings.HasSuffix(base, ".sh") || strings.HasSuffix(base, ".bash") {
		return true
	}
	switch base {
	case "install", "setup", "configure", "postinstall", "preinstall", "makefile", "run":
		return true
	}
	return false
}

func parseArchive(data []byte) *container {
	c := &container{format: FormatArchive}
	if isZip(data) {
		c.scanZip(data)
		return c
	}
	body, warn := decompressAny(data)
	if body == nil {
		c.warning = warn
		return c
	}
	c.extractTarScripts(body, func(name string) (string, bool) {
		if looksLikeInstaller(name) {
			return name, true
		}
		return "", false
	})
	return c
}

func (c *container) scanZip(data []byte) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		c.warning = "zip: " + err.Error()
		return
	}
	count := 0
	for _, f := range zr.File {
		if count >= maxMembers || len(c.scripts) >= maxScripts {
			c.warning = joinWarn(c.warning, "zip member cap reached")
			return
		}
		count++
		if f.FileInfo().IsDir() || f.UncompressedSize64 > maxScriptBytes {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(rc, maxScriptBytes))
		rc.Close()
		if looksLikeInstaller(f.Name) || bytes.HasPrefix(body, []byte("#!")) {
			c.scripts = append(c.scripts, scriptSource{name: f.Name, body: string(body)})
			c.scriptNames = append(c.scriptNames, f.Name)
		}
	}
}
