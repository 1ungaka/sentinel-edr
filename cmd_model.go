package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/s-b-repo/cau/internal/model"
	"github.com/s-b-repo/cau/internal/release"
	"github.com/s-b-repo/cau/internal/report"
	"github.com/s-b-repo/cau/internal/safefs"
	"github.com/s-b-repo/cau/internal/sidecar"
)

// The model registry is the signed catalogue of the artifacts the engine may
// run. It names each artifact by its digest, requires an SBOM and a model
// card for every one of them, and records which version is in force.
//
// The registry does not run anything: inference belongs to a sidecar. What
// this command does is answer "which artifact may run, is it the one that was
// signed, and how do I go back to the previous one".
func modelUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau model <subcommand> [flags]

  list       list the registered artifacts and the version in force
  verify     check the registry's signature and every artifact against it
  promote    make a version the one in force (the previous one is remembered)
  rollback   go back to the version that was in force before
  card       print an artifact's model card
  score      ask the inference sidecar to score a file with a registered model

A model is a file an attacker would love to replace, so the registry is
signed with the same trust anchor as the release manifest and the update
bundle, over its own canonical bytes and in its own signature domain. Every
artifact carries an SBOM and a model card, and both are checked against their
digests.

Flags:
  --registry <path>  the registry document (default: models/registry.json)
  --sig <path>       the detached signature over the registry
  --pubkey <file>    the trusted public key (hex); also read from $CAU_MODEL_PUBKEY
  --model <id>       the artifact to act on, as name@version
  --file <path>      the file to score (score)
  --sidecar <path>   the sidecar's unix socket (score)
  --fail-at <score>  exit non-zero when the model scores at or above this (score)
  --format <fmt>     text or json (default text)
  --out <path>       write the result here instead of stdout

Examples:
  cau model list
  cau model verify --sig models/registry.sig --pubkey pub.hex
  cau model promote --model embedder@1.2.0
  cau model rollback
`)
}

// envModelPubKey names the environment variable that holds the trusted public
// key for the model registry.
const envModelPubKey = "CAU_MODEL_PUBKEY"

// defaultModelRegistry is where the registry lives when nothing says
// otherwise.
const defaultModelRegistry = "models/registry.json"

// defaultModelSidecar is where the inference sidecar listens when nothing says
// otherwise.
const defaultModelSidecar = "/run/cau-model.sock"

func cmdModel(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		modelUsage(stderr)
		return report.ExitUsage
	}
	switch args[0] {
	case "list":
		return modelList(args[1:], stdout, stderr)
	case "verify":
		return modelVerify(args[1:], stdout, stderr)
	case "promote":
		return modelPromote(args[1:], stdout, stderr)
	case "rollback":
		return modelRollback(args[1:], stdout, stderr)
	case "card":
		return modelCard(args[1:], stdout, stderr)
	case "score":
		return modelScore(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		modelUsage(stdout)
		return report.ExitOK
	default:
		modelUsage(stderr)
		return fail(stderr, report.ExitUsage, "unknown model subcommand %q", args[0])
	}
}

// modelFlags are the flags every model subcommand takes.
type modelFlags struct {
	registry *string
	sig      *string
	pubkey   *string
	model    *string
	file     *string
	sidecar  *string
	failAt   *float64
	format   *string
	out      *string
}

func newModelFlags(fs *flag.FlagSet) modelFlags {
	return modelFlags{
		registry: fs.String("registry", defaultModelRegistry, "the registry document"),
		sig:      fs.String("sig", "", "the detached signature over the registry"),
		pubkey:   fs.String("pubkey", "", "the trusted public key (hex)"),
		model:    fs.String("model", "", "the artifact to act on, as name@version"),
		file:     fs.String("file", "", "the file to score"),
		sidecar:  fs.String("sidecar", defaultModelSidecar, "the inference sidecar's unix socket"),
		failAt:   fs.Float64("fail-at", -1, "exit non-zero when the model scores at or above this"),
		format:   fs.String("format", "text", "text or json"),
		out:      fs.String("out", "", "write the result here instead of stdout"),
	}
}

// maxModelDocumentBytes bounds a document the registry tooling reads: the
// registry, its signature, a model card and a public key are all small, and a
// FIFO in their place would hang the read.
const maxModelDocumentBytes = 16 << 20

// loadModelRegistry reads the registry document.
func loadModelRegistry(path string) (*model.Registry, string, error) {
	data, err := safefs.ReadFile(path, maxModelDocumentBytes)
	if err != nil {
		return nil, "", fmt.Errorf("model registry: %w", err)
	}
	r, err := model.Parse(data)
	if err != nil {
		return nil, "", err
	}
	return r, filepath.Dir(path), nil
}

// modelList prints the catalogue.
func modelList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("model list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	f := newModelFlags(fs)
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	r, _, err := loadModelRegistry(*f.registry)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if *f.format == "json" {
		if err := writeJSON(stdout, r); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		return report.ExitOK
	}
	fmt.Fprintf(stdout, "model registry: %s\n", *f.registry)
	if r.Active != "" {
		fmt.Fprintf(stdout, "  active : %s\n", r.Active)
	} else {
		fmt.Fprintln(stdout, "  active : (none)")
	}
	fmt.Fprintf(stdout, "  models : %d\n", len(r.Models))
	for _, m := range r.Models {
		mark := " "
		if m.ID() == r.Active {
			mark = "*"
		}
		fmt.Fprintf(stdout, "  %s %-28s %-10s %s\n", mark, m.ID(), m.Format, m.SHA256[:16])
	}
	if len(r.History) > 0 {
		fmt.Fprintf(stdout, "  history: %s\n", strings.Join(r.History, ", "))
	}
	return report.ExitOK
}

// modelVerify checks the signature and every artifact.
func modelVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("model verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	f := newModelFlags(fs)
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	r, root, err := loadModelRegistry(*f.registry)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if *f.sig == "" {
		return fail(stderr, report.ExitUsage, "model verify: --sig is required")
	}
	key, err := modelVerifyKey(*f.pubkey)
	if err != nil {
		return fail(stderr, report.ExitUsage, "%v", err)
	}
	sig, err := safefs.ReadFile(*f.sig, maxModelDocumentBytes)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "model verify: %v", err)
	}
	v := model.Verify(r, root, sig, key)

	if *f.format == "json" {
		if err := writeJSON(stdout, v); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	} else {
		fmt.Fprintf(stdout, "model registry: %s\n", v.Registry)
		fmt.Fprintf(stdout, "  models  : %d\n", v.Models)
		fmt.Fprintf(stdout, "  active  : %s\n", v.Active)
		if v.Verified {
			fmt.Fprintln(stdout, "  verified: the signature and every artifact match")
		} else {
			fmt.Fprintf(stdout, "  verified: NO (%d problem(s))\n", len(v.Problems))
			for _, p := range v.Problems {
				fmt.Fprintf(stdout, "    ✗ [%s] %s\n", p.Kind, p.Message)
			}
		}
		if v.Note != "" {
			fmt.Fprintf(stdout, "  note    : %s\n", v.Note)
		}
	}
	if !v.Verified {
		return report.ExitThreat
	}
	return report.ExitOK
}

// modelPromote makes a version the one in force.
func modelPromote(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("model promote", flag.ContinueOnError)
	fs.SetOutput(stderr)
	f := newModelFlags(fs)
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *f.model == "" {
		return fail(stderr, report.ExitUsage, "model promote: --model is required")
	}
	r, _, err := loadModelRegistry(*f.registry)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if err := r.Promote(*f.model); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	return writeModelRegistry(r, *f.registry, *f.out, stdout, stderr, "promoted")
}

// modelRollback goes back to the previous version.
func modelRollback(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("model rollback", flag.ContinueOnError)
	fs.SetOutput(stderr)
	f := newModelFlags(fs)
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	r, _, err := loadModelRegistry(*f.registry)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if err := r.Rollback(); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	return writeModelRegistry(r, *f.registry, *f.out, stdout, stderr, "rolled back to")
}

// writeModelRegistry renders the registry and writes it back.
func writeModelRegistry(r *model.Registry, path, out string, stdout, stderr io.Writer, what string) int {
	data, err := model.Marshal(r)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if out == "" {
		out = path
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	fmt.Fprintf(stdout, "%s %s; the registry at %s now has %s active.\n", what, r.Active, out, r.Active)
	fmt.Fprintln(stdout, "It is unsigned: sign it again before it is used.")
	return report.ExitOK
}

// modelCard prints an artifact's model card.
func modelCard(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("model card", flag.ContinueOnError)
	fs.SetOutput(stderr)
	f := newModelFlags(fs)
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *f.model == "" {
		return fail(stderr, report.ExitUsage, "model card: --model is required")
	}
	r, root, err := loadModelRegistry(*f.registry)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	m, ok := r.Find(*f.model)
	if !ok {
		return fail(stderr, report.ExitRunFailed, "model card: %q is not in the registry", *f.model)
	}
	if m.Card == "" {
		return fail(stderr, report.ExitRunFailed, "model card: %s has no card", m.ID())
	}
	// The card is named by the registry, and the registry may be unsigned.
	// The path is therefore checked against the registry's own directory
	// before it is opened: a registry that names a path outside it is
	// asking this command to print a file the registry does not own.
	card, err := model.ResolveArtifact(root, m.Card)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "model card: %v", err)
	}
	data, err := safefs.ReadFile(card, maxModelDocumentBytes)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if _, err := stdout.Write(data); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	return report.ExitOK
}

// modelScore asks the sidecar to score a file with a registered model.
//
// The engine does not do inference: the bytes go to the sidecar, which holds
// the runtime and the artifacts, and the answer comes back as scores. A model
// that is not in the registry is not asked for: which artifact may run is the
// registry's decision.
func modelScore(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("model score", flag.ContinueOnError)
	fs.SetOutput(stderr)
	f := newModelFlags(fs)
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *f.model == "" {
		return fail(stderr, report.ExitUsage, "model score: --model is required")
	}
	if *f.file == "" {
		return fail(stderr, report.ExitUsage, "model score: --file is required")
	}
	r, _, err := loadModelRegistry(*f.registry)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	m, ok := r.Find(*f.model)
	if !ok {
		return fail(stderr, report.ExitRunFailed, "model score: %q is not in the registry", *f.model)
	}
	data, err := safefs.ReadFile(*f.file, maxModelDocumentBytes)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "model score: %v", err)
	}
	client := &sidecar.Client{Socket: *f.sidecar}
	resp, err := client.Score(sidecar.Request{Model: m.ID(), ModelBytes: data})
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "model score: %v", err)
	}
	if *f.format == "json" {
		if err := writeJSON(stdout, resp); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	} else {
		fmt.Fprintf(stdout, "model %s scored %s\n", m.ID(), *f.file)
		for _, name := range sortedKeys(resp.Scores) {
			label := resp.Labels[name]
			if label != "" {
				label = " (" + label + ")"
			}
			fmt.Fprintf(stdout, "  %-24s %.4f%s\n", name, resp.Scores[name], label)
		}
		if resp.Version != "" {
			fmt.Fprintf(stdout, "  sidecar: %s\n", resp.Version)
		}
	}
	if *f.failAt >= 0 {
		for _, score := range resp.Scores {
			if score >= *f.failAt {
				return report.ExitThreat
			}
		}
	}
	return report.ExitOK
}

// sortedKeys lists a map's keys in order.
func sortedKeys(m map[string]float64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// modelVerifyKey reads the trusted public key: the flag, or the environment.
func modelVerifyKey(path string) (release.VerifyKey, error) {
	var data []byte
	switch {
	case path != "":
		b, err := safefs.ReadFile(path, maxModelDocumentBytes)
		if err != nil {
			return release.VerifyKey{}, fmt.Errorf("public key: %w", err)
		}
		data = b
	case os.Getenv(envModelPubKey) != "":
		data = []byte(os.Getenv(envModelPubKey))
	default:
		return release.VerifyKey{}, fmt.Errorf("no public key: pass --pubkey or set $%s", envModelPubKey)
	}
	key, err := release.ParseVerifyKey(data)
	if err != nil {
		return release.VerifyKey{}, err
	}
	return key, nil
}
