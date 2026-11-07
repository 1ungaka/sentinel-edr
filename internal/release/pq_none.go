//go:build !go1.27 || nomldsa

package release

// Stand-in for pq_mldsa.go in a binary built with a Go toolchain older than
// 1.27, which has no crypto/mldsa (or built with the nomldsa tag, which is how
// this file is tested on a newer one).
//
// Such a binary is the Ed25519-only chain and nothing less: bare-hex keys and
// signatures work as before, and a hybrid signature still verifies on its
// Ed25519 half against an Ed25519-only key, because reading the hybrid text
// form needs no ML-DSA. What it cannot do is hold a hybrid key, so every
// attempt to load, generate or use one fails with ErrPQUnavailable. It never
// checks the Ed25519 half of a hybrid key and calls that a pass.

// PQAvailable is false: this binary cannot make or check ML-DSA signatures.
const PQAvailable = false

// PQPublicKey cannot be constructed in this build.
type PQPublicKey struct{}

// Bytes returns nothing in this build.
func (k *PQPublicKey) Bytes() []byte { return nil }

// PQPrivateKey cannot be constructed in this build.
type PQPrivateKey struct{}

// Bytes returns nothing in this build.
func (k *PQPrivateKey) Bytes() []byte { return nil }

// Public returns nothing in this build.
func (k *PQPrivateKey) Public() *PQPublicKey { return nil }

func pqNewPublicKey([]byte) (*PQPublicKey, error)   { return nil, ErrPQUnavailable }
func pqNewPrivateKey([]byte) (*PQPrivateKey, error) { return nil, ErrPQUnavailable }
func pqGenerateKey() (*PQPrivateKey, error)         { return nil, ErrPQUnavailable }

func pqSign(*PQPrivateKey, []byte, string) ([]byte, error) { return nil, ErrPQUnavailable }
func pqVerify(*PQPublicKey, []byte, []byte, string) error  { return ErrPQUnavailable }
