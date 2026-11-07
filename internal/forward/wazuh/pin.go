package wazuh

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Certificate pinning for the manager's TLS identity.
//
// Pinning the SIEM *address* says where incidents go. It does not say who
// answers there, and the usual answer — "TLS verification does" — is only true
// while every certificate authority in the host's trust store is trustworthy.
// Any one of a hundred-odd CAs can issue a certificate for the manager's name,
// so an attacker who can obtain or coerce one, or who can add a CA to the
// store, redirects the stream with verification still nominally passing.
//
// A pin removes that: the agent additionally requires the server's public key
// to be one it was told to expect. Pinning the key rather than the certificate
// is deliberate, so the manager can renew its certificate without breaking the
// agent, which is what makes the pin something an operator will actually keep.
//
// The pin value is a SHA-256 over the DER SubjectPublicKeyInfo — the same thing
// HPKP and most pinning tooling use, so `openssl x509 -pubkey | openssl pkey
// -pubin -outform der | openssl dgst -sha256 -binary | base64` produces it.

// PinPrefix is the optional algorithm prefix accepted on a pin value.
const PinPrefix = "sha256/"

// SPKIPin returns the pin value for a certificate, in the canonical
// "sha256/<base64>" form the agent logs and the operator pastes into
// configuration.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return PinPrefix + base64.StdEncoding.EncodeToString(sum[:])
}

// parsePins normalises the configured pins to raw 32-byte digests.
//
// Both base64 and hex are accepted because operators arrive with both: the
// openssl recipe above produces base64, and anything that hashed the DER with a
// shell tool produces hex. Refusing one of them would be a papercut on a
// security control that only works if people set it.
func parsePins(pins []string) ([][32]byte, error) {
	var out [][32]byte
	for _, raw := range pins {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		p = strings.TrimPrefix(p, PinPrefix)
		var sum []byte
		var err error
		if len(p) == 64 {
			sum, err = hex.DecodeString(p)
		} else {
			sum, err = base64.StdEncoding.DecodeString(p)
		}
		if err != nil || len(sum) != sha256.Size {
			return nil, fmt.Errorf("wazuh: %q is not a SHA-256 public-key pin (want %d bytes as hex or base64, optionally prefixed %q)", raw, sha256.Size, PinPrefix)
		}
		out = append(out, [32]byte(sum))
	}
	return out, nil
}

// pinVerifier returns a TLS VerifyPeerCertificate that requires some
// certificate in the presented chain to match a pin.
//
// It runs in addition to the normal chain verification, never instead of it:
// pinning is a second lock, and replacing the first with it would mean an
// expired or wrong-hostname certificate passed as long as the key matched.
//
// Any certificate in the chain may match, not just the leaf, so an operator can
// pin their own issuing CA and let the manager's leaf rotate freely underneath.
func pinVerifier(pins [][32]byte, observe func(string)) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		var first *x509.Certificate
		for _, der := range rawCerts {
			cert, err := x509.ParseCertificate(der)
			// A certificate this library cannot parse cannot match a pin
			// either, so skipping it changes nothing: the loop needs only one
			// match, and failing to find any is reported below with the key
			// that was actually offered. Chain verification has already run and
			// has its own say on a malformed chain.
			if err != nil { // audit:ok an unparseable cert cannot match a pin; the no-match case is reported below
				continue
			}
			if first == nil {
				first = cert
			}
			sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			for _, want := range pins {
				if sum == want {
					return nil
				}
			}
		}
		if first == nil {
			return errors.New("wazuh: the manager presented no parseable certificate")
		}
		// Naming what was actually offered turns a dead end into a one-step
		// fix: either the operator pins this value, or the mismatch is the
		// interception the pin exists to catch and they now have the evidence.
		if observe != nil {
			observe(SPKIPin(first))
		}
		return fmt.Errorf("wazuh: the manager's public key does not match any configured pin (it presented %s for %q)",
			SPKIPin(first), first.Subject.CommonName)
	}
}

// applyPins installs pinning on a TLS config. It is a no-op with no pins.
func applyPins(tlsCfg *tls.Config, pins []string, observe func(string)) error {
	parsed, err := parsePins(pins)
	if err != nil {
		return err
	}
	if len(parsed) == 0 {
		return nil
	}
	if tlsCfg.InsecureSkipVerify {
		// Pinning with verification disabled is a contradiction the operator
		// should resolve rather than have silently resolved for them: one of
		// the two settings is not what they meant.
		return errors.New("wazuh: a certificate pin and --wazuh-insecure were both given; pinning replaces the need to skip verification, so remove one")
	}
	tlsCfg.VerifyPeerCertificate = pinVerifier(parsed, observe)
	return nil
}
