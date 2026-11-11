package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/1ungaka/sentinel-edr/internal/hwanchor"
	"github.com/1ungaka/sentinel-edr/internal/report"
)

func hwidUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau hwid [flags]

Takes a snapshot of this host's hardware identity from sysfs and, on request,
saves it as a baseline or compares it with one. The scan itself is strictly
read-only: files under the sysfs root are opened for reading, nothing is
written, no ioctl is made and no device node is opened. The only file this
command ever writes is the one named with --record.

  DMI/SMBIOS  vendor, product, UUID, the product, board and chassis serials
              and the firmware version. The UUID and the serials need root.
  interfaces  each physical NIC's address and the kernel's addr_assign_type.
              Type 3 means the address was set by userspace, so the configured
              MAC is not the burned-in one. sysfs does not expose the
              burned-in address itself: the scan knows that the MAC was
              changed, not from what (that needs an ethtool ioctl this
              command does not make). Virtual interfaces are listed and never
              compared.
  TPM         presence, version and PCR 0-7 of the SHA-256 bank as the kernel
              reports them. No TPM quote is captured: a signed quote needs
              /dev/tpm0 and an attestation key, so the PCR values are
              unsigned evidence, not proof to a remote verifier.
  entropy     which hardware RNG the kernel has selected, or that none is.
              Its output is not tested.

Every value is labelled ok, absent, unreadable or placeholder ("Default
string", an all-zero UUID). Only ok is an identity. Whatever this host could
not prove is listed under "Unverifiable" and is never reported as verified.

Flags:
  --sysfs <dir>     sysfs root (default /sys)
  --format <fmt>    text or json (default text)
  --redact          replace serials, the UUID and MAC addresses with a
                    truncated SHA-256 ("sha256:" + 16 hex), so the snapshot
                    can be shared and still compared with another redacted
                    one. A pseudonym, not anonymity: the digest is unsalted.
  --record <file>   write the snapshot as the baseline (JSON, mode 0600)
  --force           with --record, replace an existing file
  --check <file>    compare with a baseline and list the differences

With --check a difference is one of:
  changed                 an identity differs: a DMI value, a PCR, a NIC's
                          permanent address, or a NIC whose address was
                          permanent and is now set by userspace
  not-reverified          it was an identity in the baseline and could not be
                          read as one now; it may be unchanged
  not-in-baseline         readable now, nothing in the baseline to compare
  entropy-source-changed  the active hardware RNG differs
Only "changed" sets the exit code. A baseline and a snapshot must both be
redacted or both not. A changed PCR means the measured boot chain differs: a
firmware update does that as surely as an implant.

Serials, UUIDs and MAC addresses identify one machine. The snapshot stays on
this host unless you move it.

Exit codes: 0 ok, 1 identity changed (--check only), 3 the run failed (sysfs
or the baseline could not be read, the baseline could not be written),
4 usage.
`)
}

// hwidCheck is the JSON printed with --check.
type hwidCheck struct {
	Baseline           string                `json:"baseline"`
	BaselineCapturedAt string                `json:"baseline_captured_at"`
	IdentityChanged    bool                  `json:"identity_changed"`
	Differences        []hwanchor.Difference `json:"differences"`
	Snapshot           *hwanchor.Snapshot    `json:"snapshot"`
}

func cmdHwid(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hwid", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { hwidUsage(stderr) }
	sysfs := fs.String("sysfs", hwanchor.DefaultSysfs, "sysfs root")
	format := fs.String("format", "text", "output format: text or json")
	redact := fs.Bool("redact", false, "replace serials, the UUID and MAC addresses with a truncated SHA-256")
	record := fs.String("record", "", "write the snapshot as the baseline")
	force := fs.Bool("force", false, "with --record, replace an existing file")
	check := fs.String("check", "", "compare with a baseline")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	if fs.NArg() != 0 {
		return fail(stderr, report.ExitUsage, "hwid takes no positional arguments")
	}
	if *sysfs == "" {
		return fail(stderr, report.ExitUsage, "--sysfs must name a directory")
	}
	if *record != "" && *check != "" {
		return fail(stderr, report.ExitUsage, "--record and --check are separate runs: check against the old baseline first, then record a new one")
	}
	if *force && *record == "" {
		return fail(stderr, report.ExitUsage, "--force only applies to --record")
	}

	// Read the baseline before the scan: a bad baseline fails the run without
	// output that could be mistaken for a comparison.
	var baseline *hwanchor.Snapshot
	if *check != "" {
		var err error
		if baseline, err = hwidReadBaseline(*check); err != nil {
			return fail(stderr, report.ExitRunFailed, "baseline %s: %s", report.TermSafe(*check), report.TermSafe(err.Error()))
		}
	}

	snap, err := hwanchor.Capture(hwanchor.Options{Sysfs: *sysfs})
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%s", report.TermSafe(err.Error()))
	}
	if *redact {
		snap = hwanchor.Redact(snap)
	}

	var diffs []hwanchor.Difference
	if baseline != nil {
		if baseline.Redacted != snap.Redacted {
			hint := "run without --redact, or record a redacted baseline"
			if baseline.Redacted {
				hint = "pass --redact to compare with it"
			}
			return fail(stderr, report.ExitRunFailed, "baseline %s is %s and this snapshot is %s: %s",
				report.TermSafe(*check), hwidRedactedWord(baseline.Redacted), hwidRedactedWord(snap.Redacted), hint)
		}
		if diffs, err = hwanchor.Compare(baseline, snap); err != nil {
			return fail(stderr, report.ExitRunFailed, "baseline %s: %s", report.TermSafe(*check), report.TermSafe(err.Error()))
		}
	}

	if *record != "" {
		data, err := hwanchor.Marshal(snap)
		if err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		if err := hwidWriteBaseline(*record, data, *force); err != nil {
			return fail(stderr, report.ExitRunFailed, "%s", report.TermSafe(err.Error()))
		}
		fmt.Fprintf(stderr, "[*] baseline written to %s (mode 0600)\n", report.TermSafe(*record))
	}

	changed := hwanchor.IdentityChanged(diffs)
	if *format == "json" {
		var v interface{} = snap
		if baseline != nil {
			v = hwidCheck{Baseline: *check, BaselineCapturedAt: baseline.CapturedAt, IdentityChanged: changed, Differences: diffs, Snapshot: snap}
		}
		if err := writeJSON(stdout, v); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	} else {
		writeHwidText(stdout, snap)
		if baseline != nil {
			writeHwidCheckText(stdout, *check, baseline, diffs)
		}
	}
	if changed {
		return report.ExitThreat
	}
	return report.ExitOK
}

func hwidRedactedWord(redacted bool) string {
	if redacted {
		return "redacted"
	}
	return "not redacted"
}

// hwidReadBaseline reads and validates a baseline file, bounded.
func hwidReadBaseline(path string) (*hwanchor.Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, hwidCause(err)
	}
	defer f.Close()
	if fi, serr := f.Stat(); serr != nil || !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, hwanchor.MaxSnapshotBytes+1))
	if err != nil {
		return nil, hwidCause(err)
	}
	return hwanchor.Parse(data)
}

// hwidCause is an error without the path the os package prefixes; the caller
// names the file.
func hwidCause(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// hwidWriteBaseline writes the baseline with mode 0600. Without force an
// existing file is never touched: the create is exclusive, so it also refuses
// a symbolic link. With force the new content is written beside the target
// and renamed over it, so the old baseline is replaced whole or not at all
// and a link at that path is replaced, not followed.
func hwidWriteBaseline(path string, data []byte, force bool) error {
	if !force {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; not overwritten (pass --force to replace it)", path)
		}
		if err != nil {
			return fmt.Errorf("could not create %s: %w", path, hwidCause(err))
		}
		_, werr := f.Write(data)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			os.Remove(path) // this run created it; do not leave half a baseline
			return fmt.Errorf("could not write %s: %w", path, hwidCause(werr))
		}
		return nil
	}
	if fi, err := os.Lstat(path); err == nil && fi.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".hwid-baseline-*")
	if err != nil {
		return fmt.Errorf("could not create %s: %w", path, hwidCause(err))
	}
	_, werr := tmp.Write(data)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(tmp.Name(), 0o600)
	}
	if werr == nil {
		werr = os.Rename(tmp.Name(), path)
	}
	if werr != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("could not write %s: %w", path, hwidCause(werr))
	}
	return nil
}

// hwidField renders one field. Every value and reason passes through
// TermSafe: DMI strings, interface names and a baseline file's contents are
// whatever their author wanted them to be.
func hwidField(f hwanchor.Field) string {
	safe := report.TermSafe
	switch f.State {
	case hwanchor.StateOK:
		return safe(f.Value)
	case hwanchor.StatePlaceholder:
		return `placeholder "` + safe(f.Value) + `": not an identity`
	}
	if f.Reason == "" {
		return string(f.State)
	}
	return string(f.State) + ": " + safe(f.Reason)
}

// hwidDetail is hwidField for a row that already has a state column.
func hwidDetail(f hwanchor.Field) string {
	safe := report.TermSafe
	switch f.State {
	case hwanchor.StateOK:
		return safe(f.Value)
	case hwanchor.StatePlaceholder:
		return `"` + safe(f.Value) + `": not an identity`
	}
	return safe(f.Reason)
}

func writeHwidText(w io.Writer, s *hwanchor.Snapshot) {
	safe := report.TermSafe
	fmt.Fprintf(w, "Sysfs       : %s\n", safe(s.Sysfs))
	fmt.Fprintf(w, "Captured    : %s\n", safe(s.CapturedAt))
	if s.Redacted {
		fmt.Fprintln(w, "Redacted    : yes (serials, UUID and MAC addresses are truncated SHA-256 digests)")
	}

	fmt.Fprintln(w, "DMI/SMBIOS  :")
	for _, name := range hwanchor.DMIFields {
		f, ok := s.DMI[name]
		if !ok {
			f = hwanchor.Field{State: hwanchor.StateAbsent}
		}
		fmt.Fprintf(w, "  %-15s %-11s %s\n", name, hwidState(f.State), hwidDetail(f))
	}

	fmt.Fprintf(w, "Interfaces  : %d physical, %d virtual\n", len(s.Interfaces), len(s.VirtualInterfaces))
	diverged := 0
	for _, i := range s.Interfaces {
		assign := i.Assignment
		if i.AssignType.State == hwanchor.StateOK {
			assign += ", addr_assign_type " + safe(i.AssignType.Value)
		}
		mark := ""
		if i.Divergence {
			diverged++
			mark = "  MAC CHANGED"
		}
		fmt.Fprintf(w, "  %-15s %s  (%s)%s\n", safe(i.Name), hwidField(i.Address), assign, mark)
		if !i.PermanentAddress.OK() && !i.Divergence { // divergence is explained once, below
			fmt.Fprintf(w, "    permanent address %s\n", hwidField(i.PermanentAddress))
		}
	}
	if diverged > 0 {
		fmt.Fprintf(w, "  %d interface(s) carry an address set by userspace. sysfs does not expose the\n"+
			"  burned-in address, so this shows that the MAC was changed, not from what.\n"+
			"  MAC randomisation, bonding and `ip link set address` all produce this.\n", diverged)
	}
	if n := len(s.VirtualInterfaces); n > 0 {
		const maxShown = 16
		var names []string
		for i, v := range s.VirtualInterfaces {
			if i >= maxShown {
				names = append(names, fmt.Sprintf("+%d more", n-maxShown))
				break
			}
			names = append(names, safe(v.Name))
		}
		fmt.Fprintf(w, "  virtual (not compared): %s\n", strings.Join(names, ", "))
	}

	t := s.TPM
	switch {
	case t.State != hwanchor.StateOK:
		fmt.Fprintf(w, "TPM         : %s\n", hwidField(hwanchor.Field{State: t.State, Reason: t.Reason}))
	default:
		fmt.Fprintf(w, "TPM         : present, version %s\n", hwidField(t.VersionMajor))
		for _, p := range t.PCRs {
			fmt.Fprintf(w, "  PCR %d (%s) : %s\n", p.Index, safe(t.PCRBank), hwidField(p.Field))
		}
	}
	fmt.Fprintf(w, "  quote       : %s. %s\n", safe(t.Quote.Status), safe(t.Quote.Reason))

	r := s.RNG
	switch r.State {
	case hwanchor.StateOK:
		fmt.Fprintf(w, "Entropy     : hardware RNG %s", safe(r.Current))
		if len(r.Available) > 0 {
			fmt.Fprintf(w, " (available: %s)", safe(strings.Join(r.Available, ", ")))
		}
		fmt.Fprintln(w)
	default:
		fmt.Fprintf(w, "Entropy     : hardware RNG %s. %s\n", safe(r.Current), safe(r.Reason))
	}

	fmt.Fprintf(w, "Unverifiable: %d anchor(s) this host could not prove in this run\n", len(s.Unverifiable))
	for _, u := range s.Unverifiable {
		fmt.Fprintf(w, "  %-34s %-12s %s\n", safe(u.Anchor), hwidState(u.State), safe(u.Reason))
	}
	if len(s.Notes) > 0 {
		fmt.Fprintln(w, "Not inspected / limits:")
		for _, n := range s.Notes {
			fmt.Fprintf(w, "  - %s\n", safe(n))
		}
	}
}

// hwidState is the state column; an unknown state from a file is escaped
// like any other untrusted text.
func hwidState(s hwanchor.State) string { return report.TermSafe(string(s)) }

func writeHwidCheckText(w io.Writer, path string, baseline *hwanchor.Snapshot, diffs []hwanchor.Difference) {
	safe := report.TermSafe
	fmt.Fprintf(w, "Baseline    : %s (captured %s)\n", safe(path), safe(baseline.CapturedAt))
	count := map[hwanchor.DiffKind]int{}
	for _, d := range diffs {
		count[d.Kind]++
	}
	fmt.Fprintf(w, "Differences : %d changed, %d could not be re-verified, %d not in the baseline, %d entropy source\n",
		count[hwanchor.KindChanged], count[hwanchor.KindNotReverified], count[hwanchor.KindNotInBaseline], count[hwanchor.KindEntropySourceChanged])
	for _, d := range diffs {
		fmt.Fprintf(w, "  [%s] %s\n", safe(string(d.Kind)), safe(d.Anchor))
		switch {
		case d.Baseline != "" && d.Current != "":
			fmt.Fprintf(w, "    baseline %s, now %s\n", safe(d.Baseline), safe(d.Current))
		case d.Baseline != "":
			fmt.Fprintf(w, "    baseline %s\n", safe(d.Baseline))
		case d.Current != "":
			fmt.Fprintf(w, "    now %s\n", safe(d.Current))
		}
		fmt.Fprintf(w, "    %s\n", safe(d.Detail))
	}
	if hwanchor.IdentityChanged(diffs) {
		fmt.Fprintln(w, "Verdict     : IDENTITY CHANGED")
	} else {
		fmt.Fprintln(w, "Verdict     : no identity change among the anchors that could be compared")
	}
	if n := len(diffs) - count[hwanchor.KindChanged]; n > 0 {
		fmt.Fprintf(w, "Note        : %d difference(s) are not \"changed\" and do not affect the exit code.\n"+
			"              \"could not be re-verified\" means an anchor that was an identity in the\n"+
			"              baseline could not be read as one now: it may be unchanged, and this run\n"+
			"              cannot say. Run as root to read the UUID and the serials.\n", n)
	}
}
