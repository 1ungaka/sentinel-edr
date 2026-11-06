package hwanchor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// A sysfs attribute is at most one page. Something far larger is not read
// into memory and its first page is not recorded as an identity.
func TestOversizedAttributeIsRefused(t *testing.T) {
	tr := fullTree(t)
	big := bytes.Repeat([]byte("A"), 1<<20)
	for _, rel := range []string{dmiDir + "product_serial", eth0Dir + "address", tpmDir + "pcr-sha256/0", rngDir + "rng_current", rngDir + "rng_available"} {
		tr.write(rel, string(big))
	}
	s := capture(t, tr)
	if f := s.DMI["product_serial"]; f.State != StateUnreadable || f.Value != "" || !strings.Contains(f.Reason, "4096") {
		t.Errorf("1 MiB product_serial = state %s, %d-byte value, reason %q", f.State, len(f.Value), f.Reason)
	}
	if eth := iface(t, s, "eth0"); eth.Address.State != StateUnreadable || eth.PermanentAddress.State != StateUnreadable {
		t.Errorf("1 MiB address: %+v", eth)
	}
	if p := s.TPM.PCRs[0]; p.State != StateUnreadable || p.Value != "" {
		t.Errorf("1 MiB PCR: state %s, %d-byte value", p.State, len(p.Value))
	}
	if s.RNG.State != StateUnreadable || len(s.RNG.Available) != 0 {
		t.Errorf("1 MiB rng_current: %+v", s.RNG)
	}
	raw, err := Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 64<<10 {
		t.Errorf("the snapshot of a tree with 1 MiB attributes is %d bytes", len(raw))
	}

	// Exactly one page is still an attribute; one byte more is not.
	tr.write(dmiDir+"product_serial", strings.Repeat("S", maxAttrBytes))
	tr.write(dmiDir+"board_serial", strings.Repeat("S", maxAttrBytes+1))
	s = capture(t, tr)
	if f := s.DMI["product_serial"]; f.State != StateOK || len(f.Value) != maxAttrBytes {
		t.Errorf("4096-byte attribute: state %s, %d bytes", f.State, len(f.Value))
	}
	if f := s.DMI["board_serial"]; f.State != StateUnreadable {
		t.Errorf("4097-byte attribute: state %s", f.State)
	}
}

// DMI strings are whatever the firmware (or a hypervisor's operator) put
// there. They are recorded faithfully, as valid UTF-8, and a baseline holding
// them still compares equal after a save and load.
func TestControlCharactersSurviveRoundTrip(t *testing.T) {
	tr := fullTree(t)
	hostile := "ACME\x1b[2J\x1b[H\x00\x07 Corp\r\nVerdict: clean\u202e\xff\xfe"
	tr.write(dmiDir+"sys_vendor", hostile+"\n")
	tr.write(dmiDir+"product_serial", "SER\x1b]0;owned\x07IAL\n")
	tr.write(rngDir+"rng_current", "rng\x1b[31m\n")
	s := capture(t, tr)

	f := s.DMI["sys_vendor"]
	if f.State != StateOK || !utf8.ValidString(f.Value) {
		t.Fatalf("sys_vendor = %+v (valid UTF-8: %v)", f, utf8.ValidString(f.Value))
	}
	if !strings.Contains(f.Value, "\x1b[2J") || !strings.Contains(f.Value, "\u202e") || !strings.Contains(f.Value, "\uFFFD") {
		t.Errorf("the value was altered beyond replacing invalid UTF-8: %q", f.Value)
	}

	raw, err := Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	// The encoder escapes C0 control bytes, so the file holds none besides
	// its own newlines. (It does not escape bidi controls or DEL: a baseline
	// is JSON for a parser, and the text renderer is what escapes those.)
	for i, b := range raw {
		if b < 0x20 && b != '\n' {
			t.Fatalf("raw control byte %#x at offset %d of the encoded snapshot", b, i)
		}
	}
	loaded, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if diffs := compare(t, loaded, capture(t, tr)); len(diffs) != 0 {
		t.Errorf("a baseline with control characters differs from its own tree: %v", kinds(diffs))
	}
	if loaded.DMI["sys_vendor"].Value != f.Value {
		t.Errorf("round trip changed the value: %q -> %q", f.Value, loaded.DMI["sys_vendor"].Value)
	}
}

func TestHostileInterfaceNames(t *testing.T) {
	tr := fullTree(t)
	// As long as a file name can be: no interface is called that.
	huge := strings.Repeat("A", 255)
	tr.write("class/net/"+huge+"/address", testMAC+"\n")
	tr.write("class/net/"+huge+"/addr_assign_type", "3\n")
	tr.mkdir("class/net/" + huge + "/device")
	// The kernel accepts an escape character in an interface name.
	evil := "e\x1b[2Jth\xff"
	tr.write("class/net/"+evil+"/address", "a4:bb:6d:00:11:22\n")
	tr.write("class/net/"+evil+"/addr_assign_type", "0\n")
	tr.mkdir("class/net/" + evil + "/device")

	s := capture(t, tr)
	if len(s.Interfaces) != 2 {
		t.Fatalf("interfaces: %+v", s.Interfaces)
	}
	for _, i := range s.Interfaces {
		if len(i.Name) > 4*maxIfName || !utf8.ValidString(i.Name) {
			t.Errorf("interface name not bounded or not valid UTF-8: %q", i.Name)
		}
	}
	got := iface(t, s, "e\x1b[2Jth\uFFFD")
	if got.PermanentAddress.Value != "a4:bb:6d:00:11:22" {
		t.Errorf("the oddly named interface was not read: %+v", got)
	}
	raw, _ := Marshal(s)
	if strings.Contains(string(raw), "AAAAAAAAAAAAAAAAAAAA") {
		t.Error("the 255-byte name reached the snapshot")
	}
	if len(s.Notes) != 1 || !strings.Contains(s.Notes[0], "1 class/net entries have names longer than 15 bytes") {
		t.Errorf("notes = %v", s.Notes)
	}
	if _, err := Parse(raw); err != nil {
		t.Errorf("the snapshot does not parse back: %v", err)
	}
}

func TestInterfaceCap(t *testing.T) {
	tr := emptyTree(t)
	const n = maxInterfaces + 76
	for i := 0; i < n; i++ {
		dir := fmt.Sprintf("class/net/eth%d", i)
		tr.write(dir+"/address", fmt.Sprintf("02:00:00:00:%02x:%02x\n", i>>8, i&0xff))
		tr.write(dir+"/addr_assign_type", "0\n")
		tr.write(dir+"/device", "")
	}
	s := capture(t, tr)
	if len(s.Interfaces) != maxInterfaces {
		t.Errorf("%d interfaces inventoried, want the cap of %d", len(s.Interfaces), maxInterfaces)
	}
	found := false
	for _, note := range s.Notes {
		found = found || strings.Contains(note, "more than 1024 entries")
	}
	if !found {
		t.Errorf("the cap was reached silently: %v", s.Notes)
	}
	raw, err := Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > MaxSnapshotBytes {
		t.Errorf("a full snapshot is %d bytes, over MaxSnapshotBytes", len(raw))
	}
	if _, err := Parse(raw); err != nil {
		t.Errorf("a full snapshot does not parse back: %v", err)
	}
}

// Nothing below the root may lead out of it. A link that does is recorded as
// unreadable and what it points at is never opened.
func TestLinksOutOfTheRootAreNotFollowed(t *testing.T) {
	outside := t.TempDir()
	secret := "TOP-SECRET-OUTSIDE-THE-ROOT"
	os.WriteFile(filepath.Join(outside, "secret"), []byte(secret+"\n"), 0o644)
	os.MkdirAll(filepath.Join(outside, "nic", "device"), 0o755)
	os.WriteFile(filepath.Join(outside, "nic", "address"), []byte("de:ad:be:ef:00:01\n"), 0o644)
	os.WriteFile(filepath.Join(outside, "nic", "addr_assign_type"), []byte("0\n"), 0o644)
	os.MkdirAll(filepath.Join(outside, "tpm0", "pcr-sha256"), 0o755)
	os.WriteFile(filepath.Join(outside, "tpm0", "pcr-sha256", "0"), []byte(strings.Repeat("e", 64)+"\n"), 0o644)

	tr := fullTree(t)
	up := strings.Repeat("../", 12)
	rel, err := filepath.Rel(tr.root, outside)
	if err != nil {
		t.Fatal(err)
	}
	rel = filepath.ToSlash(rel)

	// An attribute that is an absolute link, and one that climbs out.
	tr.remove(dmiDir + "product_serial")
	tr.link(dmiDir+"product_serial", filepath.Join(outside, "secret"))
	tr.remove(dmiDir + "board_serial")
	tr.link(dmiDir+"board_serial", "../../../../"+rel+"/secret") // four levels up is the root
	// A link that climbs far above the filesystem root.
	tr.remove(dmiDir + "chassis_serial")
	tr.link(dmiDir+"chassis_serial", up+"etc/hostname")
	// A link that leaves the root and comes back in is still refused.
	tr.remove(dmiDir + "bios_date")
	tr.link(dmiDir+"bios_date", "../../../../../"+filepath.Base(tr.root)+"/"+dmiDir+"bios_vendor")
	// A loop.
	tr.remove(dmiDir + "bios_version")
	tr.link(dmiDir+"bios_version", "bios_version")
	// A whole interface and a whole TPM that live outside.
	tr.link("class/net/evil0", "../../"+rel+"/nic")
	tr.remove("class/tpm/tpm0")
	tr.link("class/tpm/tpm0", "../../"+rel+"/tpm0")

	s := capture(t, tr)
	for _, name := range []string{"product_serial", "board_serial", "chassis_serial", "bios_date"} {
		f := s.DMI[name]
		if f.State != StateUnreadable || f.Value != "" || !strings.Contains(f.Reason, "outside the sysfs root") {
			t.Errorf("%s = %+v, want unreadable: outside the root", name, f)
		}
	}
	if f := s.DMI["bios_version"]; f.State != StateUnreadable || !strings.Contains(f.Reason, "too many symbolic links") {
		t.Errorf("link loop: %+v", f)
	}
	for _, i := range s.Interfaces {
		if i.Name == "evil0" {
			t.Errorf("an interface outside the root was inventoried: %+v", i)
		}
	}
	if s.TPM.State != StateUnreadable || len(s.TPM.PCRs) != 0 {
		t.Errorf("a TPM outside the root: %+v", s.TPM)
	}
	raw, _ := Marshal(s)
	for _, leak := range []string{secret, "de:ad:be:ef:00:01", strings.Repeat("e", 64)} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("content from outside the root reached the snapshot: %s", leak)
		}
	}
	noted := false
	for _, n := range s.Notes {
		noted = noted || (strings.Contains(n, "evil0") && strings.Contains(n, "outside the sysfs root"))
	}
	if !noted {
		t.Errorf("the skipped interface was not noted: %v", s.Notes)
	}
	// The links inside the root, which is how sysfs is built, still work.
	if s.DMI["product_uuid"].State != StateOK || iface(t, s, "eth0").PermanentAddress.State != StateOK {
		t.Errorf("in-root links stopped working: %+v", s.DMI["product_uuid"])
	}
}

// Things that are not regular files where an attribute should be.
func TestAttributeThatIsNotAFile(t *testing.T) {
	tr := fullTree(t)
	tr.remove(dmiDir + "product_serial")
	tr.mkdir(dmiDir + "product_serial")
	tr.remove(dmiDir + "board_serial")
	tr.link(dmiDir+"board_serial", "missing-target")
	tr.remove("class/net/eth0")
	tr.link("class/net/eth0", "../../devices/nowhere/net/eth0")
	tr.remove(tpmDir + "pcr-sha256")
	tr.write(tpmDir+"pcr-sha256", "not a directory\n")
	s := capture(t, tr)
	if f := s.DMI["product_serial"]; f.State != StateUnreadable || !strings.Contains(f.Reason, "not a regular file") {
		t.Errorf("a directory as an attribute: %+v", f)
	}
	if f := s.DMI["board_serial"]; f.State != StateAbsent {
		t.Errorf("a dangling link: %+v, want absent", f)
	}
	if len(s.Interfaces) != 0 {
		t.Errorf("a dangling interface link was inventoried: %+v", s.Interfaces)
	}
	for _, p := range s.TPM.PCRs {
		if p.State != StateUnreadable {
			t.Errorf("PCR %d under a file named pcr-sha256: %+v", p.Index, p)
		}
	}
}

func TestUnreadableDirectories(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	tr := fullTree(t)
	for _, rel := range []string{"class/net", "devices/virtual/dmi/id"} {
		p := tr.path(rel)
		if err := os.Chmod(p, 0o000); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(p, 0o755)
	}
	s := capture(t, tr)
	if len(s.Interfaces) != 0 {
		t.Errorf("interfaces from an unreadable class/net: %+v", s.Interfaces)
	}
	listed := false
	for _, u := range s.Unverifiable {
		listed = listed || (u.Anchor == "net" && u.State == StateUnreadable)
	}
	if !listed {
		t.Errorf("an unreadable class/net is not in the unverifiable list: %v", anchors(s))
	}
	for _, name := range DMIFields {
		if f := s.DMI[name]; f.State != StateUnreadable {
			t.Errorf("%s under an unreadable directory = %+v, want unreadable, not absent", name, f)
		}
	}
}

// Whatever the tree holds, the encoded snapshot is valid JSON.
func TestGarbageTreeEncodes(t *testing.T) {
	tr := emptyTree(t)
	junk := string([]byte{0xff, 0xfe, 0x00, 0x1b, '[', '2', 'J', 0x80, '\n', 0x9b, '"', '\\'})
	for _, name := range DMIFields {
		tr.write("class/dmi/id/"+name, junk)
	}
	tr.write("class/net/x/address", junk)
	tr.write("class/net/x/addr_assign_type", junk)
	tr.write("class/net/x/device", junk)
	tr.write("class/tpm/tpm0/tpm_version_major", junk)
	for i := 0; i < PCRCount; i++ {
		tr.write(fmt.Sprintf("class/tpm/tpm0/pcr-sha256/%d", i), junk)
	}
	tr.write("class/misc/hw_random/rng_current", junk)
	tr.write("class/misc/hw_random/rng_available", strings.Repeat(junk+" ", 300))
	s := capture(t, tr)
	raw, err := Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) {
		t.Fatal("the encoded snapshot is not valid JSON")
	}
	if len(s.RNG.Available) > 64 {
		t.Errorf("%d available RNGs listed", len(s.RNG.Available))
	}
	loaded, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if diffs := compare(t, loaded, capture(t, tr)); len(diffs) != 0 {
		t.Errorf("a garbage tree differs from its own baseline: %v", kinds(diffs))
	}
}

// The package reads and nothing else. This parses its own non-test source
// and fails on any call that can modify the filesystem, any write through a
// file handle, and any import that could reach a device, a process or the
// network. The os package is held to an allowlist, so a new way of writing
// cannot slip in under a name the denylist does not know.
func TestPackageNeverWrites(t *testing.T) {
	forbidden := map[string]bool{
		"os.Create": true, "os.OpenFile": true, "os.WriteFile": true, "os.Remove": true, "os.RemoveAll": true,
		"os.Rename": true, "os.Mkdir": true, "os.MkdirAll": true, "os.MkdirTemp": true, "os.CreateTemp": true,
		"os.Truncate": true, "os.Chmod": true, "os.Chown": true, "os.Lchown": true, "os.Chtimes": true,
		"os.Symlink": true, "os.Link": true, "os.NewFile": true, "os.OpenRoot": true, "os.OpenInRoot": true,
		"os.StartProcess": true, "os.CopyFS": true, "os.Setenv": true, "os.Chdir": true, "os.Pipe": true,
		"io.WriteString": true,
	}
	allowedOS := map[string]bool{"Open": true, "Lstat": true, "Readlink": true, "SameFile": true}
	forbiddenImports := map[string]bool{
		"os/exec": true, "syscall": true, "unsafe": true, "net": true, "net/http": true,
		"golang.org/x/sys/unix": true, "plugin": true, "os/signal": true,
	}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	files := 0
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			files++
			for _, imp := range file.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if forbiddenImports[path] || strings.HasPrefix(path, "net/") || strings.HasPrefix(path, "golang.org/x/sys") {
					t.Errorf("%s imports %s: this package reads sysfs files and nothing else", name, path)
				}
				if imp.Name != nil && path == "os" {
					t.Errorf("%s imports os under another name, which would hide it from this gate", name)
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, isIdent := sel.X.(*ast.Ident)
				if isIdent && forbidden[id.Name+"."+sel.Sel.Name] {
					t.Errorf("%s: %s.%s can modify the system; this package is read-only by construction",
						fset.Position(sel.Pos()), id.Name, sel.Sel.Name)
				}
				if isIdent && id.Name == "os" && !allowedOS[sel.Sel.Name] {
					t.Errorf("%s: os.%s is not on the read-only allowlist %v", fset.Position(sel.Pos()), sel.Sel.Name, allowedOS)
				}
				// Methods that write through an open handle, whatever the
				// handle is called. The JSON encoder writes to a
				// bytes.Buffer through Encode, which is not on this list.
				switch sel.Sel.Name {
				case "Write", "WriteString", "WriteAt", "WriteTo", "ReadFrom", "Truncate", "Sync", "Chmod", "Chown", "SetDeadline":
					t.Errorf("%s: .%s writes through a handle", fset.Position(sel.Pos()), sel.Sel.Name)
				}
				return true
			})
		}
	}
	if files < 6 {
		t.Fatalf("only %d source files were checked; the gate is not looking at the package", files)
	}
}
