package linuxpkg

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// Docker / OCI image tarballs (`docker save`, `podman save`, an OCI layout) are
// plain tar archives. The highest-signal build-time tradecraft does not need the
// layers unpacked at all: the image *config* JSON records, in its history, the
// exact shell commands each layer was built from (`created_by`), plus the
// runtime Cmd / Entrypoint / Env. A `RUN curl … | sh`, a reverse-shell
// ENTRYPOINT, or a credential-stuffed ENV is all readable there. We additionally
// walk the (bounded) layer tars for well-known entrypoint scripts.

func isDockerImage(data []byte) bool {
	body, _ := decompressAny(data)
	if body == nil {
		body = data
	}
	return tarHasMember(body, func(n string) bool {
		n = strings.TrimPrefix(n, "./")
		return n == "manifest.json" || n == "oci-layout" || n == "index.json"
	})
}

// dockerManifestEntry is one entry of a `docker save` manifest.json.
type dockerManifestEntry struct {
	Config string   `json:"Config"`
	Layers []string `json:"Layers"`
}

// dockerConfig is the subset of an image config JSON we score.
type dockerConfig struct {
	Config struct {
		Cmd        []string `json:"Cmd"`
		Entrypoint []string `json:"Entrypoint"`
		Env        []string `json:"Env"`
		User       string   `json:"User"`
	} `json:"config"`
	History []struct {
		CreatedBy  string `json:"created_by"`
		EmptyLayer bool   `json:"empty_layer"`
	} `json:"history"`
}

// entrypointNames are layer paths that commonly hold the container's launch
// script; worth pulling out of the (bounded) layer walk.
func isEntrypointScript(name string) bool {
	base := name[strings.LastIndexByte(name, '/')+1:]
	switch base {
	case "entrypoint.sh", "docker-entrypoint.sh", "run.sh", "start.sh", "init.sh":
		return true
	}
	return strings.Contains(name, "docker-entrypoint.d/")
}

func parseDocker(data []byte) *container {
	c := &container{format: FormatDocker}
	body, warn := decompressAny(data)
	if body == nil {
		body = data
	}
	if warn != "" {
		c.warning = warn
	}

	members := slurpTar(body)
	if members == nil {
		c.warning = joinWarn(c.warning, "could not read image tar")
		return c
	}

	// 1) Image config: history created_by lines + runtime Cmd/Entrypoint/Env.
	for _, cfgName := range dockerConfigNames(members) {
		var cfg dockerConfig
		if err := json.Unmarshal(members[cfgName], &cfg); err != nil {
			continue
		}
		for i, h := range cfg.History {
			if cmd := dockerStripShellPrefix(h.CreatedBy); cmd != "" {
				c.scripts = append(c.scripts, scriptSource{name: "layer#" + itoa(i), body: capStr(cmd)})
			}
		}
		if s := strings.Join(cfg.Config.Entrypoint, " "); s != "" {
			c.scripts = append(c.scripts, scriptSource{name: "ENTRYPOINT", body: capStr(s)})
		}
		if s := strings.Join(cfg.Config.Cmd, " "); s != "" {
			c.scripts = append(c.scripts, scriptSource{name: "CMD", body: capStr(s)})
		}
		if len(cfg.Config.Env) > 0 {
			c.scripts = append(c.scripts, scriptSource{name: "ENV", body: capStr(strings.Join(cfg.Config.Env, "\n"))})
		}
		c.scriptNames = append(c.scriptNames, "image-config")
	}

	// 2) Layer tars: pull out well-known entrypoint scripts (bounded).
	for name, blob := range members {
		if len(c.scripts) >= maxScripts {
			break
		}
		if !strings.HasSuffix(name, "layer.tar") && !strings.HasPrefix(strings.TrimPrefix(name, "./"), "blobs/") {
			continue
		}
		layer, _ := decompressAny(blob) // gzip layers handled; xz/zstd skipped
		if layer == nil {
			continue
		}
		c.extractTarScripts(layer, func(n string) (string, bool) {
			if isEntrypointScript(n) {
				return "layer:" + n, true
			}
			return "", false
		})
	}

	if len(c.scripts) == 0 && c.warning == "" {
		c.warning = "no build history or entrypoint scripts found in image"
	}
	return c
}

// dockerConfigNames returns the image-config member names: those referenced by
// manifest.json, falling back to any top-level sha256-looking .json blob.
func dockerConfigNames(members map[string][]byte) []string {
	var out []string
	if mj, ok := members["manifest.json"]; ok {
		var entries []dockerManifestEntry
		if json.Unmarshal(mj, &entries) == nil {
			for _, e := range entries {
				if e.Config != "" && members[e.Config] != nil {
					out = append(out, e.Config)
				}
			}
		}
	}
	if len(out) == 0 {
		// OCI / fallback: any .json that parses as an image config (has history).
		for name, blob := range members {
			if !strings.HasSuffix(name, ".json") || name == "manifest.json" || name == "index.json" {
				continue
			}
			if bytes.Contains(blob, []byte("\"history\"")) || bytes.Contains(blob, []byte("\"config\"")) {
				out = append(out, name)
			}
		}
	}
	return out
}

// dockerStripShellPrefix normalises a layer's created_by into the command it
// actually ran, dropping the common "/bin/sh -c " and BuildKit "RUN " prefixes
// so the script heuristic sees the payload, not the wrapper.
func dockerStripShellPrefix(s string) string {
	s = strings.TrimSpace(s)
	for _, p := range []string{"|", "/bin/sh -c ", "/bin/bash -c ", "RUN ", "CMD ", "ENTRYPOINT ", "#(nop) "} {
		if strings.HasPrefix(s, p) {
			s = strings.TrimSpace(strings.TrimPrefix(s, p))
		}
	}
	// BuildKit records as `RUN /bin/sh -c <cmd> # buildkit`; trim trailing marker.
	if i := strings.Index(s, " # buildkit"); i >= 0 {
		s = s[:i]
	}
	return s
}

// slurpTar reads a tar into a bounded name→bytes map for random access.
func slurpTar(tarData []byte) map[string][]byte {
	tr := tar.NewReader(bytes.NewReader(tarData))
	out := make(map[string][]byte)
	for i := 0; i < maxMembers; i++ {
		hdr, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			if len(out) == 0 {
				return nil
			}
			return out
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(tr, maxDecompressBytes))
		out[strings.TrimPrefix(hdr.Name, "./")] = b
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
