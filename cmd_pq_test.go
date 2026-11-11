//go:build go1.27 && !nomldsa

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/internal/release"
	"github.com/1ungaka/sentinel-edr/internal/report"
	"github.com/1ungaka/sentinel-edr/internal/updater"
)

// End-to-end tests of the hybrid (Ed25519 + ML-DSA-65) chain through the CLI:
// keygen -> bundle update -> update --from, and keygen -> bundle checksums ->
// verify-self, plus every way of presenting less than both signatures.

// pqHybridKeys runs `cau bundle keygen --hybrid` and returns the two files.
func pqHybridKeys(t *testing.T, extra ...string) (privFile, pubFile string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "keys")
	args := append([]string{"bundle", "keygen", "--out", dir, "--hybrid"}, extra...)
	code, out, errOut := runCLI(t, args...)
	if code != report.ExitOK {
		t.Fatalf("keygen --hybrid: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(out, "wrote Ed25519 + ML-DSA-65 signing key") {
		t.Errorf("keygen output: %q", out)
	}
	privFile, pubFile = filepath.Join(dir, "cau-release.key"), filepath.Join(dir, "cau-release.pub")
	if st, err := os.Stat(privFile); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("hybrid private key: %v, mode %v", err, st.Mode().Perm())
	}
	return privFile, pubFile
}

// pqHybridBundle runs `cau bundle update` with a hybrid key.
func pqHybridBundle(t *testing.T, privFile string, payload []byte) string {
	t.Helper()
	db := pqWrite(t, filepath.Join(t.TempDir(), "hashes.txt"), payload)
	out := filepath.Join(t.TempDir(), "bundle")
	code, stdout, errOut := runCLI(t, "bundle", "update", "--db", db, "--sign-key", privFile, "--out", out, "--db-version", "2026.11.06", "--min-engine", "0.1.0")
	if code != report.ExitOK {
		t.Fatalf("bundle update: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(stdout, "signed with: Ed25519 + ML-DSA-65") {
		t.Errorf("bundle update output: %q", stdout)
	}
	return out
}

// pqSigHalves reads the two hex values out of a hybrid signature file.
func pqSigHalves(t *testing.T, path string) (edHex, pqHex string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 3 || lines[0] != "cau-hybrid-v1 signature" {
		t.Fatalf("%s is not a hybrid signature: %d lines, header %q", path, len(lines), lines[0])
	}
	return strings.TrimPrefix(lines[1], "ed25519: "), strings.TrimPrefix(lines[2], "ml-dsa-65: ")
}

func pqFlip(s string, i int) string {
	c := byte('0')
	if s[i] == '0' {
		c = '1'
	}
	return s[:i] + string(c) + s[i+1:]
}

func pqHybridSigDoc(edHex, pqHex string) []byte {
	return []byte("cau-hybrid-v1 signature\ned25519: " + edHex + "\nml-dsa-65: " + pqHex + "\n")
}

func TestPQHybridBundleUpdateInstalls(t *testing.T) {
	t.Setenv(envUpdateKey, "")
	privFile, pubFile := pqHybridKeys(t)
	newLine := "SHA256|" + strings.Repeat("1", 64) + "|New\n"
	bundle := pqHybridBundle(t, privFile, []byte(newLine))

	db := pqLiveDB(t)
	code, out, errOut := runCLI(t, "update", "--from", bundle, "--pubkey", pubFile, "--db", db)
	if code != report.ExitOK {
		t.Fatalf("update: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(out, "signature verified: Ed25519 + ML-DSA-65\n") || !strings.Contains(out, "installed") || errOut != "" {
		t.Errorf("out %q err %q", out, errOut)
	}
	if got, _ := os.ReadFile(db); string(got) != newLine {
		t.Errorf("db = %q", got)
	}

	// The hybrid key as the content of the environment variable, newlines and all.
	pubData, _ := os.ReadFile(pubFile)
	t.Setenv(envUpdateKey, strings.TrimSpace(string(pubData)))
	code, out, errOut = runCLI(t, "update", "--from", bundle, "--db", pqLiveDB(t), "--dry-run")
	if code != report.ExitOK || !strings.Contains(out, "signature verified: Ed25519 + ML-DSA-65") {
		t.Errorf("key from $%s: code=%d out %q err %q", envUpdateKey, code, out, errOut)
	}
}

// Everything that is less than both valid signatures, presented to a verifier
// that trusts the hybrid key: exit 1, database untouched.
func TestPQHybridKeyRefusesAnythingLessThanBoth(t *testing.T) {
	t.Setenv(envUpdateKey, "")
	privFile, pubFile := pqHybridKeys(t)
	_, otherPub := pqHybridKeys(t)
	bundle := pqHybridBundle(t, privFile, []byte("SHA256|"+strings.Repeat("1", 64)+"|New\n"))
	sigPath := filepath.Join(bundle, updater.SignatureName)
	genuine, _ := os.ReadFile(sigPath)
	edHex, pqHex := pqSigHalves(t, sigPath)
	edRaw, _ := hex.DecodeString(edHex)

	// The same manifest bytes signed as a SHA256SUMS by the same key.
	privData, _ := os.ReadFile(privFile)
	key, err := release.ParseSignKey(privData)
	if err != nil {
		t.Fatal(err)
	}
	mb, _ := os.ReadFile(filepath.Join(bundle, updater.ManifestName))
	asChecksums, err := release.SignChecksums(mb, key)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		sig  []byte
		key  string
		want string
	}{
		{"ML-DSA half stripped, hex Ed25519 left", []byte(edHex), pubFile, "stripped"},
		{"ML-DSA half stripped, raw Ed25519 left", edRaw, pubFile, "stripped"},
		{"hybrid frame cut after the Ed25519 line", []byte("cau-hybrid-v1 signature\ned25519: " + edHex + "\n"), pubFile, "truncated"},
		{"Ed25519 half tampered", pqHybridSigDoc(pqFlip(edHex, 9), pqHex), pubFile, "the Ed25519 signature is not valid"},
		{"ML-DSA half tampered", pqHybridSigDoc(edHex, pqFlip(pqHex, 9)), pubFile, "the ML-DSA-65 signature is not valid"},
		{"a checksums signature presented for the manifest", asChecksums, pubFile, "the ML-DSA-65 signature is not valid"},
		{"another hybrid key", genuine, otherPub, "neither the Ed25519 nor the ML-DSA-65 signature is valid"},
		{"unknown version", []byte(strings.Replace(string(genuine), "cau-hybrid-v1", "cau-hybrid-v2", 1)), pubFile, "unsupported hybrid format version"},
		{"unknown algorithm tag", []byte(strings.Replace(string(genuine), "ml-dsa-65:", "ml-dsa-87:", 1)), pubFile, "unknown algorithm tag"},
		{"ML-DSA component truncated", pqHybridSigDoc(edHex, pqHex[:len(pqHex)-2]), pubFile, "the ml-dsa-65 component is 6616 hex characters"},
		{"trailing bytes", append(append([]byte(nil), genuine...), "extra\n"...), pubFile, "unexpected trailing data"},
	}
	for _, tc := range cases {
		pqWrite(t, sigPath, tc.sig)
		db := pqLiveDB(t)
		code, out, errOut := runCLI(t, "update", "--from", bundle, "--pubkey", tc.key, "--db", db)
		if code != report.ExitThreat || !strings.Contains(errOut, tc.want) {
			t.Errorf("%s: code=%d (want %d), stderr %q (want %q)", tc.name, code, report.ExitThreat, errOut, tc.want)
		}
		if strings.Contains(out, "verified") {
			t.Errorf("%s: a refusal printed %q", tc.name, out)
		}
		if got, _ := os.ReadFile(db); !strings.Contains(string(got), "|Old") {
			t.Errorf("%s: the database changed", tc.name)
		}
	}

	// And the untouched bundle still installs, so the refusals above are about
	// the signatures and nothing else.
	pqWrite(t, sigPath, genuine)
	if code, _, errOut := runCLI(t, "update", "--from", bundle, "--pubkey", pubFile, "--db", pqLiveDB(t)); code != report.ExitOK {
		t.Fatalf("genuine bundle: code=%d err=%s", code, errOut)
	}
}

// The migration path: an existing Ed25519 release key is upgraded with
// --ed25519-key. A host that still pins only the old Ed25519 public key
// verifies the hybrid-signed release and is told what it did not check; a
// host that pins the hybrid key checks both; and an Ed25519-only release is
// refused by the hybrid key and accepted by the old one.
func TestPQHybridUpgradeKeepsOldKeyHoldersWorking(t *testing.T) {
	t.Setenv(envUpdateKey, "")
	oldPub, oldPriv := pqCompatKey()
	scratch := t.TempDir()
	oldPrivFile := pqWrite(t, filepath.Join(scratch, "priv.hex"), []byte(hex.EncodeToString(oldPriv.Seed())))
	oldPubFile := pqWrite(t, filepath.Join(scratch, "release-pubkey.hex"), []byte(hex.EncodeToString(oldPub)))

	privFile, pubFile := pqHybridKeys(t, "--ed25519-key", oldPrivFile)
	pubData, _ := os.ReadFile(pubFile)
	if !strings.Contains(string(pubData), "ed25519: "+hex.EncodeToString(oldPub)+"\n") {
		t.Fatal("the upgraded key did not keep the existing Ed25519 half")
	}
	bundle := pqHybridBundle(t, privFile, []byte("SHA256|"+strings.Repeat("1", 64)+"|New\n"))

	code, out, errOut := runCLI(t, "update", "--from", bundle, "--pubkey", oldPubFile, "--db", pqLiveDB(t))
	if code != report.ExitOK {
		t.Fatalf("old key holder: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(out, "signature verified: Ed25519\n") || strings.Contains(out, "ML-DSA") {
		t.Errorf("old key holder: out %q", out)
	}
	if !strings.Contains(errOut, "[WARN]") || !strings.Contains(errOut, "ML-DSA-65") || !strings.Contains(errOut, "NOT checked") {
		t.Errorf("old key holder was not told the post-quantum signature went unchecked: %q", errOut)
	}
	code, out, errOut = runCLI(t, "update", "--from", bundle, "--pubkey", pubFile, "--db", pqLiveDB(t))
	if code != report.ExitOK || !strings.Contains(out, "signature verified: Ed25519 + ML-DSA-65") || errOut != "" {
		t.Errorf("new key holder: code=%d out %q err %q", code, out, errOut)
	}

	// An Ed25519-only release by the same Ed25519 key, as CI makes today.
	legacy, _ := pqLegacyBundle(t, []byte("SHA256|"+strings.Repeat("2", 64)+"|Legacy\n"), "hex")
	if code, _, errOut := runCLI(t, "update", "--from", legacy, "--pubkey", oldPubFile, "--db", pqLiveDB(t)); code != report.ExitOK {
		t.Errorf("Ed25519 release, Ed25519 key: code=%d err=%s", code, errOut)
	}
	db := pqLiveDB(t)
	code, _, errOut = runCLI(t, "update", "--from", legacy, "--pubkey", pubFile, "--db", db)
	if code != report.ExitThreat || !strings.Contains(errOut, "the trusted key is hybrid") {
		t.Errorf("Ed25519 release, hybrid key: code=%d err=%q", code, errOut)
	}
	if got, _ := os.ReadFile(db); !strings.Contains(string(got), "|Old") {
		t.Error("an Ed25519-only release installed under a hybrid key")
	}

	// Upgrading a key that is already hybrid is refused.
	if code, _, errOut := runCLI(t, "bundle", "keygen", "--out", filepath.Join(scratch, "again"), "--hybrid", "--ed25519-key", privFile); code != report.ExitRunFailed || !strings.Contains(errOut, "already a hybrid key") {
		t.Errorf("upgrade of a hybrid key: code=%d err=%q", code, errOut)
	}
}

func TestPQHybridChecksumsVerifySelf(t *testing.T) {
	t.Setenv(envUpdateKey, "")
	privFile, pubFile := pqHybridKeys(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	work := t.TempDir()
	other := pqWrite(t, filepath.Join(work, "hashes.txt"), []byte("x"))
	code, stdout, errOut := runCLI(t, "bundle", "checksums", "--sign-key", privFile, "--out", work, exe, other)
	if code != report.ExitOK {
		t.Fatalf("bundle checksums: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(stdout, "signed with: Ed25519 + ML-DSA-65") {
		t.Errorf("bundle checksums output: %q", stdout)
	}
	sigPath := filepath.Join(work, release.SigName)
	genuine, _ := os.ReadFile(sigPath)
	edHex, pqHex := pqSigHalves(t, sigPath)

	code, out, errOut := runCLI(t, "verify-self", "--from", work, "--pubkey", pubFile)
	if code != report.ExitOK {
		t.Fatalf("verify-self: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(out, "signature verified: Ed25519 + ML-DSA-65\n") || !strings.Contains(out, "matches the signed release manifest") || errOut != "" {
		t.Errorf("out %q err %q", out, errOut)
	}

	// The Ed25519 half on its own is a genuine Ed25519 signature, and the
	// holder of only the Ed25519 public key accepts the hybrid release.
	pubData, _ := os.ReadFile(pubFile)
	hybridPub, err := release.ParseVerifyKey(pubData)
	if err != nil {
		t.Fatal(err)
	}
	edPubFile := pqWrite(t, filepath.Join(t.TempDir(), "ed.pub"), []byte(hex.EncodeToString(hybridPub.Ed25519)))
	code, out, errOut = runCLI(t, "verify-self", "--from", work, "--pubkey", edPubFile)
	if code != report.ExitOK || !strings.Contains(out, "signature verified: Ed25519\n") || !strings.Contains(errOut, "NOT checked") {
		t.Errorf("Ed25519-only key: code=%d out %q err %q", code, out, errOut)
	}

	// An update-manifest signature over the same SHA256SUMS bytes.
	privData, _ := os.ReadFile(privFile)
	key, _ := release.ParseSignKey(privData)
	sums, _ := os.ReadFile(filepath.Join(work, release.SumsName))
	asManifest, err := release.SignDetached(sums, key, release.DomainUpdateManifest)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		sig  []byte
		want string
	}{
		{"ML-DSA half stripped", []byte(edHex), "stripped"},
		{"signed with the Ed25519 half alone", []byte(hex.EncodeToString(ed25519.Sign(key.Ed25519, sums))), "stripped"},
		{"Ed25519 half tampered", pqHybridSigDoc(pqFlip(edHex, 20), pqHex), "the Ed25519 signature is not valid"},
		{"ML-DSA half tampered", pqHybridSigDoc(edHex, pqFlip(pqHex, 20)), "the ML-DSA-65 signature is not valid"},
		{"an update-manifest signature presented for SHA256SUMS", asManifest, "the ML-DSA-65 signature is not valid"},
		{"Ed25519 component truncated", pqHybridSigDoc(edHex[:100], pqHex), "the ed25519 component is 100 hex characters"},
	}
	for _, tc := range cases {
		pqWrite(t, sigPath, tc.sig)
		code, out, errOut := runCLI(t, "verify-self", "--from", work, "--pubkey", pubFile)
		if code != report.ExitThreat || !strings.Contains(errOut, tc.want) || !strings.Contains(errOut, "SHA256SUMS signature does not verify") {
			t.Errorf("%s: code=%d stderr %q (want %q)", tc.name, code, errOut, tc.want)
		}
		if strings.Contains(out, "verified") {
			t.Errorf("%s: a refusal printed %q", tc.name, out)
		}
	}
	pqWrite(t, sigPath, genuine)
	pqWrite(t, filepath.Join(work, release.SumsName), append(sums, ' '))
	if code, _, errOut := runCLI(t, "verify-self", "--from", work, "--pubkey", pubFile); code != report.ExitThreat || !strings.Contains(errOut, "neither") {
		t.Errorf("tampered SHA256SUMS: code=%d err=%q", code, errOut)
	}
}

// A hybrid key that is named and is not usable is a run failure (exit 3) with
// the reason. It is never "no key", and never its Ed25519 half on its own:
// each of these bundles would install if the Ed25519 half were quietly used.
func TestPQHybridKeyConfigurationErrorsNeverDowngrade(t *testing.T) {
	t.Setenv(envUpdateKey, "")
	privFile, pubFile := pqHybridKeys(t)
	bundle := pqHybridBundle(t, privFile, []byte("payload"))
	pubData, _ := os.ReadFile(pubFile)
	lines := strings.Split(strings.TrimSuffix(string(pubData), "\n"), "\n")
	scratch := t.TempDir()
	file := func(name, content string) string {
		return pqWrite(t, filepath.Join(scratch, name), []byte(content))
	}

	cases := []struct {
		name string
		key  string
		want string
	}{
		{"ML-DSA line missing", file("cut.pub", lines[0]+"\n"+lines[1]+"\n"), "truncated: the ml-dsa-65 component is missing"},
		{"ML-DSA component truncated", file("short.pub", lines[0]+"\n"+lines[1]+"\n"+lines[2][:2000]+"\n"), "the ml-dsa-65 component is 1989 hex characters"},
		{"unknown version", file("v9.pub", strings.Replace(string(pubData), "cau-hybrid-v1", "cau-hybrid-v9", 1)), "unsupported hybrid format version"},
		{"unknown algorithm tag", file("alg.pub", strings.Replace(string(pubData), "ml-dsa-65:", "ml-dsa-44:", 1)), "unknown algorithm tag"},
		{"trailing bytes", file("trail.pub", string(pubData)+"more\n"), "unexpected trailing data"},
		{"the private key file given as --pubkey", privFile, "this is a hybrid private-key, not a hybrid public-key"},
		{"a signature file given as --pubkey", filepath.Join(bundle, updater.SignatureName), "this is a hybrid signature, not a hybrid public-key"},
		{"a file far too large to be a key", file("big.pub", strings.Repeat("a", 200<<10)), "larger than"},
	}
	for _, tc := range cases {
		db := pqLiveDB(t)
		code, out, errOut := runCLI(t, "update", "--from", bundle, "--pubkey", tc.key, "--db", db)
		if code != report.ExitRunFailed || !strings.Contains(errOut, tc.want) {
			t.Errorf("update, %s: code=%d (want %d), stderr %q (want %q)", tc.name, code, report.ExitRunFailed, errOut, tc.want)
		}
		if out != "" {
			t.Errorf("update, %s: printed %q", tc.name, out)
		}
		if got, _ := os.ReadFile(db); !strings.Contains(string(got), "|Old") {
			t.Errorf("update, %s: the database changed", tc.name)
		}
		if code, _, _ := runCLI(t, "verify-self", "--from", bundle, "--pubkey", tc.key); code != report.ExitRunFailed {
			t.Errorf("verify-self, %s: code=%d, want %d", tc.name, code, report.ExitRunFailed)
		}
	}
	t.Setenv(envUpdateKey, lines[0]+"\n"+lines[1])
	if code, _, errOut := runCLI(t, "update", "--from", bundle, "--db", pqLiveDB(t)); code != report.ExitRunFailed || !strings.Contains(errOut, "truncated") {
		t.Errorf("truncated hybrid key in $%s: code=%d err=%q", envUpdateKey, code, errOut)
	}
	t.Setenv(envUpdateKey, "")

	// The producer side: a public key, or a damaged private key, never signs.
	db := pqWrite(t, filepath.Join(scratch, "hashes.txt"), []byte("x"))
	privData, _ := os.ReadFile(privFile)
	for name, keyFile := range map[string]string{
		"public key as --sign-key":    pubFile,
		"truncated hybrid --sign-key": file("cut.key", strings.SplitAfterN(string(privData), "\n", 3)[0]+strings.SplitAfterN(string(privData), "\n", 3)[1]),
	} {
		out := filepath.Join(scratch, "out-"+strings.ReplaceAll(name, " ", "-"))
		if code, _, _ := runCLI(t, "bundle", "update", "--db", db, "--sign-key", keyFile, "--out", out); code != report.ExitRunFailed {
			t.Errorf("bundle update, %s: code=%d", name, code)
		}
		if _, err := os.Stat(filepath.Join(out, updater.SignatureName)); err == nil {
			t.Errorf("bundle update, %s: a signature was written", name)
		}
		if code, _, _ := runCLI(t, "bundle", "checksums", "--sign-key", keyFile, "--out", out, db); code != report.ExitRunFailed {
			t.Errorf("bundle checksums, %s: code=%d", name, code)
		}
		if _, err := os.Stat(filepath.Join(out, release.SigName)); err == nil {
			t.Errorf("bundle checksums, %s: a signature was written", name)
		}
	}
}

// Anti-rollback is unchanged and still applied to a hybrid-signed bundle.
func TestPQHybridUpdateStillRefusesARollback(t *testing.T) {
	t.Setenv(envUpdateKey, "")
	privFile, pubFile := pqHybridKeys(t)
	privData, _ := os.ReadFile(privFile)
	key, err := release.ParseSignKey(privData)
	if err != nil {
		t.Fatal(err)
	}
	dated := func(payload, created string) string {
		dir := t.TempDir()
		m := updater.BuildManifest([]byte(payload), "v", "0.1.0")
		m.Created = created
		mb, _ := json.Marshal(m)
		sig, err := release.SignDetached(mb, key, release.DomainUpdateManifest)
		if err != nil {
			t.Fatal(err)
		}
		pqWrite(t, filepath.Join(dir, updater.PayloadName), []byte(payload))
		pqWrite(t, filepath.Join(dir, updater.ManifestName), mb)
		pqWrite(t, filepath.Join(dir, updater.SignatureName), sig)
		return dir
	}
	db := filepath.Join(t.TempDir(), "hashes.txt")
	newLine := "SHA256|" + strings.Repeat("1", 64) + "|New\n"
	oldLine := "SHA256|" + strings.Repeat("2", 64) + "|Old\n"
	if code, _, errOut := runCLI(t, "update", "--from", dated(newLine, "2026-06-01T00:00:00Z"), "--pubkey", pubFile, "--db", db); code != report.ExitOK {
		t.Fatalf("install: %d %s", code, errOut)
	}
	older := dated(oldLine, "2026-01-01T00:00:00Z")
	code, out, errOut := runCLI(t, "update", "--from", older, "--pubkey", pubFile, "--db", db)
	if code != report.ExitThreat || !strings.Contains(errOut, "--allow-downgrade") {
		t.Fatalf("rollback: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(out, "signature verified: Ed25519 + ML-DSA-65") {
		t.Errorf("the older bundle's signatures are genuine and should have been reported as such: %q", out)
	}
	if got, _ := os.ReadFile(db); string(got) != newLine {
		t.Fatalf("db changed: %q", got)
	}
	if code, _, _ := runCLI(t, "update", "--from", older, "--pubkey", pubFile, "--db", db, "--dry-run"); code != report.ExitThreat {
		t.Fatalf("dry-run: code=%d", code)
	}
	if code, _, errOut := runCLI(t, "update", "--from", older, "--pubkey", pubFile, "--db", db, "--allow-downgrade"); code != report.ExitOK {
		t.Fatalf("--allow-downgrade: %d %s", code, errOut)
	}
}
