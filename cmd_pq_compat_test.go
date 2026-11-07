package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/internal/release"
	"github.com/s-b-repo/cau/internal/report"
	"github.com/s-b-repo/cau/internal/updater"
)

// Backward compatibility of the Ed25519-only release chain through the CLI,
// in every build (with or without ML-DSA). Every artifact here is made with
// crypto/ed25519 directly, in the on-disk forms a release has always
// published: nothing goes through the hybrid-capable signer. If one of these
// fails, an existing release, key or signature has stopped verifying.

// pqCompatKey is a fixed Ed25519 keypair.
func pqCompatKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(0x80 + i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

func pqWrite(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// pqLegacyBundle writes an update bundle as an Ed25519-only release does.
// sigForm is "hex" or "raw". It returns the bundle dir and the hex key file.
func pqLegacyBundle(t *testing.T, payload []byte, sigForm string) (dir, pubFile string) {
	t.Helper()
	pub, priv := pqCompatKey()
	dir = t.TempDir()
	mb, err := json.MarshalIndent(updater.BuildManifest(payload, "2026.11.02", "0.1.0"), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, mb)
	if sigForm == "hex" {
		sig = []byte(hex.EncodeToString(sig))
	}
	pqWrite(t, filepath.Join(dir, updater.PayloadName), payload)
	pqWrite(t, filepath.Join(dir, updater.ManifestName), mb)
	pqWrite(t, filepath.Join(dir, updater.SignatureName), sig)
	pubFile = pqWrite(t, filepath.Join(t.TempDir(), "release-pubkey.hex"), []byte(hex.EncodeToString(pub)+"\n"))
	return dir, pubFile
}

func pqLiveDB(t *testing.T) string {
	t.Helper()
	return pqWrite(t, filepath.Join(t.TempDir(), "hashes.txt"), []byte("SHA256|"+strings.Repeat("0", 64)+"|Old\n"))
}

func TestPQCompatEd25519UpdateInstallsAsBefore(t *testing.T) {
	t.Setenv(envUpdateKey, "")
	newLine := "SHA256|" + strings.Repeat("1", 64) + "|New\n"
	for _, form := range []string{"hex", "raw"} {
		dir, pub := pqLegacyBundle(t, []byte(newLine), form)
		db := pqLiveDB(t)
		code, out, errOut := runCLI(t, "update", "--from", dir, "--pubkey", pub, "--db", db)
		if code != report.ExitOK {
			t.Fatalf("%s signature: code=%d err=%s", form, code, errOut)
		}
		if !strings.Contains(out, "[*] verified bundle: db_version 2026.11.02, min-engine 0.1.0, ") || !strings.Contains(out, "installed") {
			t.Errorf("%s: output changed: %q", form, out)
		}
		if !strings.Contains(out, "signature verified: Ed25519\n") {
			t.Errorf("%s: output does not say what was checked: %q", form, out)
		}
		if errOut != "" {
			t.Errorf("%s: an Ed25519-only release with an Ed25519 key printed to stderr: %q", form, errOut)
		}
		if got, _ := os.ReadFile(db); string(got) != newLine {
			t.Errorf("%s: db = %q", form, got)
		}
	}

	// The key from the environment, as content, instead of --pubkey.
	pub, _ := pqCompatKey()
	dir, _ := pqLegacyBundle(t, []byte(newLine), "hex")
	t.Setenv(envUpdateKey, hex.EncodeToString(pub))
	if code, _, errOut := runCLI(t, "update", "--from", dir, "--db", pqLiveDB(t)); code != report.ExitOK {
		t.Fatalf("key from $%s: code=%d err=%s", envUpdateKey, code, errOut)
	}
}

func TestPQCompatEd25519UpdateExitCodesAsBefore(t *testing.T) {
	t.Setenv(envUpdateKey, "")
	dir, pub := pqLegacyBundle(t, []byte("payload"), "hex")
	scratch := t.TempDir()
	otherPub := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	wrongKey := pqWrite(t, filepath.Join(scratch, "other.pub"), []byte(hex.EncodeToString(otherPub)))
	garbage := pqWrite(t, filepath.Join(scratch, "garbage.pub"), []byte("this is not a key\n"))
	short := pqWrite(t, filepath.Join(scratch, "short.pub"), []byte(hex.EncodeToString(otherPub[:16])))
	empty := pqWrite(t, filepath.Join(scratch, "empty.pub"), nil)
	badHybrid := pqWrite(t, filepath.Join(scratch, "v2.pub"), []byte("cau-hybrid-v2 public-key\ned25519: 00\nml-dsa-65: 00\n"))

	tampered := t.TempDir()
	for _, n := range []string{updater.PayloadName, updater.ManifestName, updater.SignatureName} {
		data, _ := os.ReadFile(filepath.Join(dir, n))
		pqWrite(t, filepath.Join(tampered, n), data)
	}
	mb, _ := os.ReadFile(filepath.Join(tampered, updater.ManifestName))
	pqWrite(t, filepath.Join(tampered, updater.ManifestName), append(mb, ' '))

	cases := []struct {
		name string
		from string
		key  string
		want int
		msg  string
	}{
		{"valid", dir, pub, report.ExitOK, ""},
		{"wrong key", dir, wrongKey, report.ExitThreat, "signature does not verify"},
		{"tampered manifest", tampered, pub, report.ExitThreat, "signature does not verify"},
		// A key that was named and is not usable is a run failure, never "no
		// key" and never a pass.
		{"missing key file", dir, filepath.Join(scratch, "absent.pub"), report.ExitRunFailed, "reading public key"},
		{"key file is not a key", dir, garbage, report.ExitRunFailed, "is not usable"},
		{"key file is too short", dir, short, report.ExitRunFailed, "public key is 16 bytes, want 32"},
		{"key file is empty", dir, empty, report.ExitRunFailed, "is not usable"},
		{"key file is a hybrid key of an unknown version", dir, badHybrid, report.ExitRunFailed, "unsupported hybrid format version"},
	}
	for _, tc := range cases {
		db := pqLiveDB(t)
		code, _, errOut := runCLI(t, "update", "--from", tc.from, "--pubkey", tc.key, "--db", db)
		if code != tc.want || !strings.Contains(errOut, tc.msg) {
			t.Errorf("%s: code=%d (want %d), stderr %q (want %q)", tc.name, code, tc.want, errOut, tc.msg)
		}
		if got, _ := os.ReadFile(db); tc.want != report.ExitOK && !strings.Contains(string(got), "|Old") {
			t.Errorf("%s: the database changed", tc.name)
		}
	}

	// The environment variable is held to the same rule.
	t.Setenv(envUpdateKey, "not a key")
	if code, _, errOut := runCLI(t, "update", "--from", dir, "--db", pqLiveDB(t)); code != report.ExitRunFailed || !strings.Contains(errOut, "$"+envUpdateKey+" is not usable") {
		t.Errorf("unusable $%s: code=%d stderr %q", envUpdateKey, code, errOut)
	}
}

// pqSelfSums writes a SHA256SUMS that lists the running test binary, so
// verify-self can go all the way to "matches".
func pqSelfSums(t *testing.T) (sumsData []byte, name string) {
	t.Helper()
	digest, name, err := release.SelfDigest()
	if err != nil {
		t.Fatal(err)
	}
	return []byte(digest + "  " + name + "\n" + strings.Repeat("c", 64) + "  hashes.txt\n"), name
}

func TestPQCompatEd25519VerifySelfAsBefore(t *testing.T) {
	t.Setenv(envUpdateKey, "")
	pub, priv := pqCompatKey()
	sums, name := pqSelfSums(t)
	raw := ed25519.Sign(priv, sums)
	pubFile := pqWrite(t, filepath.Join(t.TempDir(), "release-pubkey.hex"), []byte(hex.EncodeToString(pub)))

	for form, sig := range map[string][]byte{"hex": []byte(hex.EncodeToString(raw)), "hex + newline": []byte(hex.EncodeToString(raw) + "\n"), "raw": raw} {
		dir := t.TempDir()
		pqWrite(t, filepath.Join(dir, release.SumsName), sums)
		pqWrite(t, filepath.Join(dir, release.SigName), sig)
		code, out, errOut := runCLI(t, "verify-self", "--from", dir, "--pubkey", pubFile)
		if code != report.ExitOK {
			t.Fatalf("%s: code=%d err=%s", form, code, errOut)
		}
		if !strings.Contains(out, "[*] verified: "+name+" (") || !strings.Contains(out, "matches the signed release manifest") {
			t.Errorf("%s: output changed: %q", form, out)
		}
		if !strings.Contains(out, "signature verified: Ed25519\n") || errOut != "" {
			t.Errorf("%s: out %q err %q", form, out, errOut)
		}
	}

	dir := t.TempDir()
	pqWrite(t, filepath.Join(dir, release.SumsName), sums)
	pqWrite(t, filepath.Join(dir, release.SigName), []byte(hex.EncodeToString(raw)))
	otherPub := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	wrongKey := pqWrite(t, filepath.Join(t.TempDir(), "other.pub"), []byte(hex.EncodeToString(otherPub)))
	if code, _, errOut := runCLI(t, "verify-self", "--from", dir, "--pubkey", wrongKey); code != report.ExitThreat || !strings.Contains(errOut, "SHA256SUMS signature does not verify") {
		t.Errorf("wrong key: code=%d err=%q", code, errOut)
	}
	if code, _, errOut := runCLI(t, "verify-self", "--from", dir, "--pubkey", pubFile, "--name", "not-listed"); code != report.ExitThreat || !strings.Contains(errOut, "not listed") {
		t.Errorf("unlisted name: code=%d err=%q", code, errOut)
	}
	if code, _, errOut := runCLI(t, "verify-self", "--from", dir, "--pubkey", filepath.Join(dir, "absent.pub")); code != report.ExitRunFailed || !strings.Contains(errOut, "reading public key") {
		t.Errorf("missing key file: code=%d err=%q", code, errOut)
	}
	if code, _, errOut := runCLI(t, "verify-self", "--from", dir); code != report.ExitRunFailed || !strings.Contains(errOut, "no trusted public key") {
		t.Errorf("no key: code=%d err=%q", code, errOut)
	}
	pqWrite(t, filepath.Join(dir, release.SumsName), append(sums, ' '))
	if code, _, errOut := runCLI(t, "verify-self", "--from", dir, "--pubkey", pubFile); code != report.ExitThreat || !strings.Contains(errOut, "signature") {
		t.Errorf("tampered SHA256SUMS: code=%d err=%q", code, errOut)
	}
}

// With an Ed25519 key, `cau bundle` writes byte for byte what it always has.
func TestPQCompatBundleWithEd25519KeyWritesTheSameBytes(t *testing.T) {
	_, priv := pqCompatKey()
	work := t.TempDir()
	for form, keyText := range map[string]string{"seed": hex.EncodeToString(priv.Seed()), "full": hex.EncodeToString(priv) + "\n"} {
		keyFile := pqWrite(t, filepath.Join(work, form+".hex"), []byte(keyText))
		db := pqWrite(t, filepath.Join(work, "hashes.txt"), []byte("SHA256|"+strings.Repeat("a", 64)+"|X\n"))

		out := filepath.Join(work, "bundle-"+form)
		code, stdout, errOut := runCLI(t, "bundle", "update", "--db", db, "--sign-key", keyFile, "--out", out, "--db-version", "v1", "--min-engine", "0.1.0")
		if code != report.ExitOK {
			t.Fatalf("%s: bundle update: code=%d err=%s", form, code, errOut)
		}
		if want := "[+] wrote signed update bundle to " + out + " (hashes.txt, manifest.json, manifest.json.sig)\n"; stdout != want {
			t.Errorf("%s: bundle update output changed:\n got %q\nwant %q", form, stdout, want)
		}
		mb, _ := os.ReadFile(filepath.Join(out, updater.ManifestName))
		sig, _ := os.ReadFile(filepath.Join(out, updater.SignatureName))
		if string(sig) != hex.EncodeToString(ed25519.Sign(priv, mb)) {
			t.Errorf("%s: manifest.json.sig is not the hex Ed25519 signature over manifest.json", form)
		}

		sumsOut := filepath.Join(work, "sums-"+form)
		code, stdout, errOut = runCLI(t, "bundle", "checksums", "--sign-key", keyFile, "--out", sumsOut, db)
		if code != report.ExitOK {
			t.Fatalf("%s: bundle checksums: code=%d err=%s", form, code, errOut)
		}
		if want := "[+] wrote SHA256SUMS and SHA256SUMS.sig over 1 file(s) to " + sumsOut + "\n"; stdout != want {
			t.Errorf("%s: bundle checksums output changed:\n got %q\nwant %q", form, stdout, want)
		}
		sums, _ := os.ReadFile(filepath.Join(sumsOut, release.SumsName))
		sig, _ = os.ReadFile(filepath.Join(sumsOut, release.SigName))
		if string(sig) != hex.EncodeToString(ed25519.Sign(priv, sums)) {
			t.Errorf("%s: SHA256SUMS.sig is not the hex Ed25519 signature over SHA256SUMS", form)
		}
	}

	// Key errors keep their exit codes.
	if code, _, _ := runCLI(t, "bundle", "update", "--db", filepath.Join(work, "hashes.txt"), "--out", work); code != report.ExitUsage {
		t.Errorf("no --sign-key: code=%d", code)
	}
	if code, _, _ := runCLI(t, "bundle", "update", "--db", filepath.Join(work, "hashes.txt"), "--sign-key", filepath.Join(work, "absent"), "--out", work); code != report.ExitRunFailed {
		t.Errorf("missing --sign-key file: code=%d", code)
	}
	bad := pqWrite(t, filepath.Join(work, "bad.hex"), []byte("zz"))
	if code, _, _ := runCLI(t, "bundle", "checksums", "--sign-key", bad, "--out", work, bad); code != report.ExitRunFailed {
		t.Errorf("unparseable --sign-key: code=%d", code)
	}
}

// `cau bundle keygen` without --hybrid writes an Ed25519 pair in the bare-hex
// forms the existing readers take, private key 0600, and never overwrites.
func TestPQCompatBundleKeygenEd25519(t *testing.T) {
	t.Setenv(envUpdateKey, "")
	dir := filepath.Join(t.TempDir(), "keys")
	code, out, errOut := runCLI(t, "bundle", "keygen", "--out", dir)
	if code != report.ExitOK {
		t.Fatalf("keygen: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(out, "wrote Ed25519 signing key") {
		t.Errorf("output: %q", out)
	}
	privFile, pubFile := filepath.Join(dir, "cau-release.key"), filepath.Join(dir, "cau-release.pub")
	if st, err := os.Stat(privFile); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("private key: %v, mode %v", err, st.Mode().Perm())
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("key directory mode %v, %v", st.Mode().Perm(), err)
	}
	privData, _ := os.ReadFile(privFile)
	pubData, _ := os.ReadFile(pubFile)
	priv, err := release.ParsePrivateKey(privData)
	if err != nil || len(strings.TrimSpace(string(privData))) != 64 {
		t.Fatalf("private key is not the bare-hex seed form: %v", err)
	}
	pub, err := release.ParsePublicKey(pubData)
	if err != nil || !pub.Equal(priv.Public()) {
		t.Fatalf("public key does not match: %v", err)
	}
	if _, err := updater.ParsePublicKey(pubData); err != nil {
		t.Errorf("updater.ParsePublicKey: %v", err)
	}

	// The pair works end to end.
	db := pqWrite(t, filepath.Join(t.TempDir(), "hashes.txt"), []byte("SHA256|"+strings.Repeat("a", 64)+"|X\n"))
	bundle := filepath.Join(t.TempDir(), "bundle")
	if code, _, e := runCLI(t, "bundle", "update", "--db", db, "--sign-key", privFile, "--out", bundle); code != report.ExitOK {
		t.Fatalf("bundle update: %d %s", code, e)
	}
	if code, _, e := runCLI(t, "update", "--from", bundle, "--pubkey", pubFile, "--db", pqLiveDB(t)); code != report.ExitOK {
		t.Fatalf("update: %d %s", code, e)
	}

	// Never overwrite, whichever of the two files is in the way.
	code, _, errOut = runCLI(t, "bundle", "keygen", "--out", dir)
	if code != report.ExitRunFailed || !strings.Contains(errOut, "refusing to overwrite") {
		t.Errorf("second keygen: code=%d err=%q", code, errOut)
	}
	if again, _ := os.ReadFile(privFile); string(again) != string(privData) {
		t.Error("the private key was rewritten")
	}
	os.Remove(privFile)
	if code, _, _ := runCLI(t, "bundle", "keygen", "--out", dir); code != report.ExitRunFailed {
		t.Errorf("keygen over an existing public key: code=%d", code)
	}
	if _, err := os.Stat(privFile); err == nil {
		t.Error("a refused keygen left a private key behind")
	}

	if code, _, _ := runCLI(t, "bundle", "keygen"); code != report.ExitUsage {
		t.Errorf("no --out: code=%d", code)
	}
	if code, _, _ := runCLI(t, "bundle", "keygen", "--out", t.TempDir(), "--ed25519-key", privFile); code != report.ExitUsage {
		t.Errorf("--ed25519-key without --hybrid: code=%d", code)
	}
	if code, _, _ := runCLI(t, "bundle", "keygen", "--out", t.TempDir(), "stray"); code != report.ExitUsage {
		t.Errorf("stray argument: code=%d", code)
	}
}

// The usage texts say what the commands now do. updateUsage and
// verifySelfUsage are not wired to --help (they were not before this change
// either: --help prints the flag set), so they are rendered directly, and the
// flag descriptions that --help does print are checked as well.
func TestPQUsageTextsDescribeBothKeyKinds(t *testing.T) {
	var update, verifySelf, bundle strings.Builder
	updateUsage(&update)
	verifySelfUsage(&verifySelf)
	bundleUsage(&bundle)
	for name, text := range map[string]string{"update": update.String(), "verify-self": verifySelf.String(), "bundle": bundle.String()} {
		for _, want := range []string{"hybrid", "ML-DSA-65", "Ed25519", "cau-hybrid-v1"} {
			if !strings.Contains(text, want) {
				t.Errorf("cau %s: usage does not mention %q", name, want)
			}
		}
		if strings.Contains(text, "%!") {
			t.Errorf("cau %s: usage has a formatting error:\n%s", name, text)
		}
	}
	if !strings.Contains(bundle.String(), "keygen") {
		t.Error("cau bundle: usage does not list keygen")
	}
	if _, out, _ := runCLI(t, "bundle", "help"); out != bundle.String() {
		t.Error("cau bundle help does not print bundleUsage")
	}
	for _, args := range [][]string{{"update", "--help"}, {"verify-self", "--help"}, {"bundle", "update", "--help"}, {"bundle", "checksums", "--help"}, {"bundle", "keygen", "--help"}} {
		_, out, errOut := runCLI(t, args...)
		if !strings.Contains(out+errOut, "hybrid") {
			t.Errorf("cau %s: the flag help does not mention hybrid keys", strings.Join(args, " "))
		}
	}
}
