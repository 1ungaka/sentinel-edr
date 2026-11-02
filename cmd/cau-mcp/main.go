// Command cau-mcp serves the CAU detection engine over the Model Context
// Protocol (JSON-RPC 2.0 on stdio). An MCP client — an LLM agent or an IDE —
// drives the engine through bounded tools (scan, explain, test/draft rules,
// coverage) with file access confined to the roots passed on the command line.
//
// No competitor ships an AV engine as MCP; this is the Phase 3 surface.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cau-edr/cau/internal/mcp"
	"github.com/cau-edr/cau/internal/resources"
	"github.com/cau-edr/cau/scanner"
	"github.com/cau-edr/cau/scanner/static"
)

// version is overridden at build time: -ldflags "-X main.version=v1.2.3".
var version = "0.4.0-dev"

const (
	serverName = "cau-mcp"
	httpPath   = "/mcp"
)

// stringList collects a repeatable flag (--root a --root b).
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ", ") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin *os.File, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet(serverName, flag.ContinueOnError)
	fs.SetOutput(stderr)

	var roots stringList
	fs.Var(&roots, "root", "allowed scan root for file-touching tools (repeatable); without any, file tools are disabled")
	db := fs.String("db", "", "signature database (default: auto-discovered)")
	rules := fs.String("rules", "", "YARA rule file or directory (default: auto-discovered)")
	fuzzyDB := fs.String("fuzzy-db", "", "fuzzy signature database (default: auto-discovered)")
	noYara := fs.Bool("no-yara", false, "disable YARA")
	noStatic := fs.Bool("no-static", false, "disable the static structural pass")
	noStego := fs.Bool("no-stego", false, "disable the invisible-codepoint pass")
	noEncChain := fs.Bool("no-encchain", false, "disable the encoded-executable pass")
	noHeur := fs.Bool("no-heuristics", false, "disable the string/API heuristics")
	noFusion := fs.Bool("no-fusion", false, "disable the fusion lattice")
	yaraTimeout := fs.Duration("yara-timeout", 10*time.Second, "per-file YARA scan budget")
	maxBytes := fs.Int64("max-bytes", mcp.DefaultMaxBytes, "per-file size cap for file tools")
	maxFiles := fs.Int("max-files", mcp.DefaultMaxDirFiles, "max files a single scan_dir may enumerate")
	httpAddr := fs.String("http", "", "serve the streamable-HTTP transport on this address (e.g. 127.0.0.1:8923) instead of stdio")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "%s %s\n", serverName, version)
		return 0
	}

	logf := func(format string, a ...interface{}) {
		fmt.Fprintf(stderr, "[cau-mcp] "+format+"\n", a...)
	}

	// ── signature database (required) ──
	dbPath, searched := resources.Find(*db, resources.EnvSignatures, resources.RelSignatures)
	if dbPath == "" {
		logf("signature database not found; pass --db or set %s (searched: %s)", resources.EnvSignatures, strings.Join(searched, ", "))
		return 1
	}
	sigDB, err := scanner.LoadSignatures(dbPath)
	if err != nil {
		logf("loading signatures: %v", err)
		return 1
	}
	logf("loaded %d hash signatures from %s", sigDB.Count(), dbPath)

	// ── YARA (optional) ──
	var ys *scanner.YaraScanner
	rulesPath := ""
	if !*noYara {
		rp, searched := resources.Find(*rules, resources.EnvRules, resources.RelRules)
		switch {
		case rp == "" && *rules == "":
			logf("YARA rules not found, YARA disabled (searched: %s)", strings.Join(searched, ", "))
		case rp == "":
			logf("YARA rules not found at %s", *rules)
			return 1
		default:
			var files int
			ys, files, err = scanner.LoadYaraRules(rp, scanner.WithTimeout(*yaraTimeout),
				scanner.WithWarnFunc(func(f string, a ...interface{}) { logf("[warn] "+f, a...) }))
			if err != nil {
				logf("YARA: %v", err)
				return 1
			}
			defer ys.Close()
			rulesPath = rp
			logf("compiled %d YARA rules from %d file(s) at %s", ys.RuleCount(), files, rp)
		}
	}

	// ── fuzzy DB (optional) ──
	var fuzzy *static.FuzzyDB
	if !*noStatic {
		if fp, _ := resources.Find(*fuzzyDB, resources.EnvFuzzy, resources.RelFuzzy); fp != "" {
			if fuzzy, err = static.LoadFuzzyDB(fp); err != nil {
				logf("loading fuzzy DB: %v", err)
				return 1
			}
			logf("loaded %d fuzzy signatures from %s", fuzzy.Count(), fp)
		}
	}

	engine := &scanner.Engine{
		DB:         sigDB,
		Yara:       ys,
		Heuristics: !*noHeur,
		Static:     !*noStatic,
		FuzzyDB:    fuzzy,
		Stego:      !*noStego,
		EncChain:   !*noEncChain,
		NoFusion:   *noFusion,
	}

	// ── sandbox ──
	sandbox, warnings, err := mcp.NewSandbox(mcp.SandboxConfig{
		Roots:       roots,
		MaxBytes:    *maxBytes,
		MaxDirFiles: *maxFiles,
	})
	if err != nil {
		logf("sandbox: %v", err)
		return 1
	}
	for _, w := range warnings {
		logf("[warn] sandbox: %s", w)
	}
	if len(roots) == 0 {
		logf("no --root given: scan_file/scan_dir/explain_verdict are disabled; hash, rule and coverage tools still work")
	} else {
		logf("scan roots: %s", strings.Join(sandbox.Roots(), ", "))
	}

	srv := mcp.NewServer(mcp.Deps{
		Engine:    engine,
		Yara:      ys,
		SigDB:     sigDB,
		Sandbox:   sandbox,
		Info:      mcp.ServerInfo{Name: serverName, Version: version},
		RulesPath: rulesPath,
		SigDBPath: dbPath,
	})

	if *httpAddr != "" {
		mux := http.NewServeMux()
		mux.Handle(httpPath, srv.HTTPHandler())
		httpSrv := &http.Server{
			Addr:              *httpAddr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}
		logf("serving MCP over HTTP on %s%s (protocol %s)", *httpAddr, httpPath, mcp.ProtocolVersion)
		if strings.HasPrefix(*httpAddr, "0.0.0.0") || strings.HasPrefix(*httpAddr, ":") {
			logf("[warn] bound to a non-loopback address: anyone who can reach it can drive the scanner within the --root sandbox")
		}
		if err := httpSrv.ListenAndServe(); err != nil {
			logf("http serve: %v", err)
			return 1
		}
		return 0
	}

	logf("serving MCP on stdio (protocol %s)", mcp.ProtocolVersion)
	if err := srv.Serve(stdin, stdout); err != nil {
		logf("serve: %v", err)
		return 1
	}
	return 0
}
