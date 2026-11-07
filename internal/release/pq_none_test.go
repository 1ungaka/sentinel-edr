//go:build !go1.27 || nomldsa

package release

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// A binary with no ML-DSA is the Ed25519-only chain and nothing less. Run with
//
//	go test -tags nomldsa ./internal/release/

func TestWithoutMLDSAAHybridKeyIsAnErrorNotADowngrade(t *testing.T) {
	if PQAvailable {
		t.Fatal("PQAvailable is true in a build without crypto/mldsa")
	}
	pub, priv := compatKey()

	// A perfectly well-formed hybrid public key: refused whole. Its Ed25519
	// half is never handed back as an Ed25519-only key.
	hybridPub := hybridDoc("public-key", hex.EncodeToString(pub), strings.Repeat("ab", PQPublicKeySize))
	k, err := ParseVerifyKey(hybridPub)
	if !errors.Is(err, ErrPQUnavailable) || !k.IsZero() {
		t.Errorf("hybrid public key: key=%+v err=%v", k, err)
	}
	hybridPriv := hybridDoc("private-key", hex.EncodeToString(priv.Seed()), strings.Repeat("cd", PQSeedSize))
	sk, err := ParseSignKey(hybridPriv)
	if !errors.Is(err, ErrPQUnavailable) || sk.Ed25519 != nil || sk.MLDSA != nil {
		t.Errorf("hybrid private key: key=%+v err=%v", sk, err)
	}
	if _, err := GenerateSignKey(true); !errors.Is(err, ErrPQUnavailable) {
		t.Errorf("GenerateSignKey(true): %v", err)
	}
	if _, err := (SignKey{Ed25519: priv}).WithNewMLDSA(); !errors.Is(err, ErrPQUnavailable) {
		t.Errorf("WithNewMLDSA: %v", err)
	}
	// A malformed hybrid key is still reported as malformed, not as unavailable.
	if _, err := ParseVerifyKey([]byte("cau-hybrid-v2 public-key\n")); err == nil || errors.Is(err, ErrPQUnavailable) {
		t.Errorf("unknown version: %v", err)
	}

	// A hybrid key assembled in memory cannot verify anything either.
	sig := hybridDoc("signature", hex.EncodeToString(ed25519.Sign(priv, compatSums)), fakePQSig)
	if _, err := VerifyChecksums(compatSums, sig, VerifyKey{Ed25519: pub, MLDSA: &PQPublicKey{}}); !errors.Is(err, ErrBadSignature) {
		t.Errorf("in-memory hybrid key: %v", err)
	}
	if _, err := SignDetached(compatSums, SignKey{Ed25519: priv, MLDSA: &PQPrivateKey{}}, DomainChecksums); err == nil {
		t.Error("signed with a hybrid key in a build without ML-DSA")
	}

	// What still works: Ed25519 keys, and a hybrid signature on its Ed25519
	// half for an Ed25519-only key (compat_test.go covers this in every build).
	if _, err := GenerateSignKey(false); err != nil {
		t.Errorf("GenerateSignKey(false): %v", err)
	}
	if c, err := VerifyChecksums(compatSums, sig, VerifyKey{Ed25519: pub}); err != nil || !c.PQUnchecked {
		t.Errorf("Ed25519-only key, hybrid signature: %+v, %v", c, err)
	}
}
