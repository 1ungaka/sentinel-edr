//go:build go1.27 && !nomldsa

package release

// The post-quantum primitive: ML-DSA-65 from the standard library's
// crypto/mldsa (FIPS 204), which exists from Go 1.27. This file is the only
// place that imports it. pq_none.go is its stand-in for an older toolchain.

import (
	"crypto/mldsa"
	"fmt"
)

// PQAvailable reports whether this binary can make and check the post-quantum
// half of a hybrid signature. It is false in a binary built with a Go
// toolchain older than 1.27 (or with the nomldsa build tag), where every
// hybrid key is an error and nothing is ever downgraded to Ed25519 quietly.
const PQAvailable = true

// pqParams is the one place the ML-DSA parameter set is chosen. The sizes and
// names in hybrid.go must agree with it: the two constants below do not
// compile if a size is wrong, and TestPQParameterSetIsConsistent checks the
// names.
func pqParams() mldsa.Parameters { return mldsa.MLDSA65() }

const (
	_ = uint(PQPublicKeySize - mldsa.MLDSA65PublicKeySize)
	_ = uint(mldsa.MLDSA65PublicKeySize - PQPublicKeySize)
	_ = uint(PQSignatureSize - mldsa.MLDSA65SignatureSize)
	_ = uint(mldsa.MLDSA65SignatureSize - PQSignatureSize)
	_ = uint(PQSeedSize - mldsa.PrivateKeySize)
	_ = uint(mldsa.PrivateKeySize - PQSeedSize)
)

// PQPublicKey is an ML-DSA-65 public key.
type PQPublicKey struct{ pk *mldsa.PublicKey }

// Bytes returns the FIPS 204 public key encoding (PQPublicKeySize bytes).
func (k *PQPublicKey) Bytes() []byte { return k.pk.Bytes() }

// PQPrivateKey is an ML-DSA-65 private key.
type PQPrivateKey struct{ sk *mldsa.PrivateKey }

// Bytes returns the private key's seed (PQSeedSize bytes).
func (k *PQPrivateKey) Bytes() []byte { return k.sk.Bytes() }

// Public returns the matching public key.
func (k *PQPrivateKey) Public() *PQPublicKey { return &PQPublicKey{pk: k.sk.PublicKey()} }

func pqNewPublicKey(raw []byte) (*PQPublicKey, error) {
	pk, err := mldsa.NewPublicKey(pqParams(), raw)
	if err != nil {
		return nil, err
	}
	return &PQPublicKey{pk: pk}, nil
}

func pqNewPrivateKey(seed []byte) (*PQPrivateKey, error) {
	sk, err := mldsa.NewPrivateKey(pqParams(), seed)
	if err != nil {
		return nil, err
	}
	return &PQPrivateKey{sk: sk}, nil
}

func pqGenerateKey() (*PQPrivateKey, error) {
	sk, err := mldsa.GenerateKey(pqParams())
	if err != nil {
		return nil, err
	}
	return &PQPrivateKey{sk: sk}, nil
}

// pqSign makes a hedged (randomised) ML-DSA signature over msg with the FIPS
// 204 context string.
func pqSign(k *PQPrivateKey, msg []byte, context string) ([]byte, error) {
	if k == nil || k.sk == nil {
		return nil, fmt.Errorf("no %s private key", PQName)
	}
	return k.sk.Sign(nil, msg, &mldsa.Options{Context: context})
}

// pqVerify returns nil only when sig is a valid ML-DSA signature over msg
// under the same context string.
func pqVerify(k *PQPublicKey, msg, sig []byte, context string) error {
	if k == nil || k.pk == nil {
		return fmt.Errorf("no %s public key", PQName)
	}
	return mldsa.Verify(k.pk, msg, sig, &mldsa.Options{Context: context})
}
