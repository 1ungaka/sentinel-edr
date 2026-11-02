package static

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// CertInfo is one certificate found in the Authenticode PKCS#7 blob.
type CertInfo struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	// SelfSigned is true when the certificate's signature verifies under its
	// own public key.
	SelfSigned bool `json:"self_signed"`
	// CodeSigning is true when the Extended Key Usage includes id-kp-codeSigning.
	CodeSigning bool `json:"code_signing"`
	// IsCA mirrors the basic-constraints CA flag.
	IsCA bool `json:"is_ca"`
	// Signer is true for the certificate that SignerInfo names as the signer.
	Signer bool `json:"signer,omitempty"`
	// SignatureAlgorithm is the certificate's own signature algorithm.
	SignatureAlgorithm string `json:"signature_algorithm"`
	// Thumbprint is the SHA-1 hex digest of the certificate's DER encoding —
	// the canonical fingerprint abused-certificate catalogs (lolcerts) key on.
	Thumbprint string `json:"thumbprint,omitempty"`
	// ThumbprintSHA256 is the SHA-256 hex digest of the DER, for sources that
	// publish the stronger fingerprint.
	ThumbprintSHA256 string `json:"thumbprint_sha256,omitempty"`
}

// Authenticode is what the parser could learn from the security directory.
//
// Verified is always false: this package extracts and inspects the chain, it
// does not validate the signature against a trust store or check that the
// digest covers the image. The Note says so in every report so a reader can
// never mistake "present and parsed" for "valid".
type Authenticode struct {
	Offset    uint32 `json:"offset"`
	Size      uint32 `json:"size"`
	Revision  uint16 `json:"revision"`
	CertType  uint16 `json:"cert_type"`
	Parsed    bool   `json:"parsed"`
	ParseErr  string `json:"parse_error,omitempty"`
	Verified  bool   `json:"verified"`
	Note      string `json:"note"`
	DigestAlg string `json:"digest_algorithm,omitempty"`
	// Certificates lists every certificate embedded in the blob, leaf first
	// when the signer could be identified.
	Certificates []CertInfo `json:"certificates,omitempty"`
	// SignerSubject is the subject of the certificate SignerInfo points at.
	SignerSubject string `json:"signer_subject,omitempty"`
	// ChainSelfContained is true when the signer chains, within the embedded
	// certificates alone, to a self-signed root. That is normal for a real
	// signature (the root is included for convenience) and also for a
	// completely self-made one; the distinction is which root it is, which this
	// package cannot judge without a trust store.
	ChainSelfContained bool `json:"chain_self_contained"`
	// ChainTerminus is the subject of the self-signed root the chain ends at,
	// or, when the chain leaves the embedded set, the issuer name it was
	// looking for. Real-world signatures usually end at an external root.
	ChainTerminus string `json:"chain_terminus,omitempty"`
	// Countersigned is true when a countersignature (timestamp) is present.
	Countersigned bool `json:"countersigned"`
}

const authenticodeNote = "signature present and parsed; chain not verified against a trust store and image digest not checked"

var (
	oidSignedData     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidCodeSigning    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidCounterSig     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}
	oidRFC3161        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}
	digestAlgorithmBy = map[string]string{
		"1.3.14.3.2.26":          "sha1",
		"2.16.840.1.101.3.4.2.1": "sha256",
		"2.16.840.1.101.3.4.2.2": "sha384",
		"2.16.840.1.101.3.4.2.3": "sha512",
		"1.2.840.113549.2.5":     "md5",
	}
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue `asn1:"set"`
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue `asn1:"set"`
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signerInfo struct {
	Version            int
	IssuerAndSerial    issuerAndSerial
	DigestAlgorithm    algorithmIdentifier
	AuthenticatedAttrs asn1.RawValue `asn1:"optional,tag:0"`
	DigestEncryptAlg   algorithmIdentifier
	EncryptedDigest    []byte
	UnauthAttrs        asn1.RawValue `asn1:"optional,tag:1"`
}

// parseAuthenticode reads the WIN_CERTIFICATE table and extracts the PKCS#7
// certificate chain. It never returns an error: every failure lands in the
// struct so the report can show "present but unparseable", which is itself a
// signal.
func parseAuthenticode(data []byte, dir DataDir) *Authenticode {
	if dir.VirtualAddress == 0 || dir.Size == 0 {
		return nil
	}
	a := &Authenticode{Offset: dir.VirtualAddress, Size: dir.Size, Note: authenticodeNote}
	off := int64(dir.VirtualAddress)
	if off+8 > int64(len(data)) {
		a.ParseErr = "security directory points past the end of the file"
		return a
	}
	o := int(off)
	length := binary.LittleEndian.Uint32(data[o:])
	a.Revision = le16(data, o+4)
	a.CertType = le16(data, o+6)
	if length < 8 {
		a.ParseErr = "WIN_CERTIFICATE length is shorter than its header"
		return a
	}
	if length > maxCertificateBytes {
		a.ParseErr = fmt.Sprintf("WIN_CERTIFICATE claims %d bytes; refusing to parse more than %d", length, maxCertificateBytes)
		return a
	}
	end := int64(o) + int64(length)
	if end > int64(len(data)) {
		a.ParseErr = "WIN_CERTIFICATE is truncated"
		return a
	}
	if a.CertType != 0x0002 { // WIN_CERT_TYPE_PKCS_SIGNED_DATA
		a.ParseErr = fmt.Sprintf("unsupported certificate type 0x%04x", a.CertType)
		return a
	}
	blob := data[o+8 : end]

	var ci contentInfo
	if _, err := asn1.Unmarshal(blob, &ci); err != nil {
		a.ParseErr = "PKCS#7 ContentInfo: " + err.Error()
		return a
	}
	if !ci.ContentType.Equal(oidSignedData) {
		a.ParseErr = "PKCS#7 content is not SignedData (" + ci.ContentType.String() + ")"
		return a
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		a.ParseErr = "PKCS#7 SignedData: " + err.Error()
		return a
	}

	// Digest algorithm (first of the set).
	if len(sd.DigestAlgorithms.Bytes) > 0 {
		var alg algorithmIdentifier
		if _, err := asn1.Unmarshal(sd.DigestAlgorithms.Bytes, &alg); err == nil {
			if name, ok := digestAlgorithmBy[alg.Algorithm.String()]; ok {
				a.DigestAlg = name
			} else {
				a.DigestAlg = alg.Algorithm.String()
			}
		}
	}

	// Certificates: a SET OF Certificate encoded with IMPLICIT [0], so Bytes is
	// a concatenation of DER certificates.
	var certs []*x509.Certificate
	rest := sd.Certificates.Bytes
	for len(rest) > 0 && len(certs) < 32 {
		var raw asn1.RawValue
		tail, err := asn1.Unmarshal(rest, &raw)
		if err != nil {
			a.ParseErr = "certificate list: " + err.Error()
			break
		}
		if c, err := x509.ParseCertificate(raw.FullBytes); err == nil {
			certs = append(certs, c)
		} else {
			a.ParseErr = "certificate: " + err.Error()
		}
		rest = tail
	}

	// Signer identification and countersignature.
	var signerIssuer []byte
	var signerSerial *big.Int
	if len(sd.SignerInfos.Bytes) > 0 {
		var si signerInfo
		if _, err := asn1.Unmarshal(sd.SignerInfos.Bytes, &si); err == nil {
			signerIssuer = si.IssuerAndSerial.Issuer.FullBytes
			signerSerial = si.IssuerAndSerial.Serial
			a.Countersigned = hasCounterSignature(si.UnauthAttrs.Bytes)
		}
	}

	a.Parsed = len(certs) > 0 || a.ParseErr == ""
	for _, c := range certs {
		info := CertInfo{
			Subject:            c.Subject.String(),
			Issuer:             c.Issuer.String(),
			Serial:             serialHex(c.SerialNumber),
			NotBefore:          c.NotBefore.UTC(),
			NotAfter:           c.NotAfter.UTC(),
			IsCA:               c.IsCA,
			SignatureAlgorithm: c.SignatureAlgorithm.String(),
		}
		sha1sum := sha1.Sum(c.Raw)
		sha256sum := sha256.Sum256(c.Raw)
		info.Thumbprint = hex.EncodeToString(sha1sum[:])
		info.ThumbprintSHA256 = hex.EncodeToString(sha256sum[:])
		info.SelfSigned = signedBy(c, c)
		for _, eku := range c.ExtKeyUsage {
			if eku == x509.ExtKeyUsageCodeSigning {
				info.CodeSigning = true
			}
		}
		for _, oid := range c.UnknownExtKeyUsage {
			if oid.Equal(oidCodeSigning) {
				info.CodeSigning = true
			}
		}
		if signerSerial != nil && c.SerialNumber != nil && c.SerialNumber.Cmp(signerSerial) == 0 &&
			bytesEqual(c.RawIssuer, signerIssuer) {
			info.Signer = true
			a.SignerSubject = info.Subject
		}
		a.Certificates = append(a.Certificates, info)
	}

	// Put the signer first; keep the rest in order.
	for i, c := range a.Certificates {
		if c.Signer && i != 0 {
			a.Certificates[0], a.Certificates[i] = a.Certificates[i], a.Certificates[0]
			certs[0], certs[i] = certs[i], certs[0]
			break
		}
	}
	a.ChainSelfContained, a.ChainTerminus = chainsToEmbeddedRoot(certs)
	return a
}

// chainsToEmbeddedRoot follows issuer links from the first certificate through
// the embedded set. It reports whether the walk ends at a self-signed
// certificate, and the issuer name the walk stopped at. For most real
// signatures that name is an external root (cross-certified kernel-mode
// chains, Microsoft roots that are never embedded): the signature can only be
// judged against a trust store, which this package does not have.
func chainsToEmbeddedRoot(certs []*x509.Certificate) (bool, string) {
	if len(certs) == 0 {
		return false, ""
	}
	cur := certs[0]
	for hops := 0; hops < len(certs)+1; hops++ {
		if signedBy(cur, cur) {
			return true, cur.Subject.String()
		}
		var next *x509.Certificate
		for _, c := range certs {
			if c == cur {
				continue
			}
			if signedBy(cur, c) {
				next = c
				break
			}
		}
		if next == nil {
			return false, cur.Issuer.String()
		}
		cur = next
	}
	return false, cur.Issuer.String()
}

// signedBy reports whether child's signature verifies under parent's key.
//
// Go refuses to verify SHA-1 (and MD5) signatures, which every code-signing
// chain issued before ~2016 uses, including roots that are still embedded in
// signed binaries today, and it refuses to treat a v3 certificate without
// basicConstraints as a CA, which describes several 1990s vendor roots. For
// those two cases the check falls back to issuer/subject name equality:
// weaker, but "issued by name under a signature Go will not verify" is the
// honest description, and the certificate list shows each certificate's
// algorithm so a reader can see which case applies.
func signedBy(child, parent *x509.Certificate) bool {
	err := child.CheckSignatureFrom(parent)
	if err == nil {
		return true
	}
	if !sameName(child.RawIssuer, child.Issuer, parent.RawSubject, parent.Subject) {
		return false
	}
	// Issuer name matches. Accept the link only for the two failure classes
	// that describe Go's policy rather than the signature: an algorithm Go
	// refuses to verify, or a 1990s/2000s root without basicConstraints that Go
	// refuses to treat as a CA. A genuine verification failure stays false.
	var insecure x509.InsecureAlgorithmError
	var constraint x509.ConstraintViolationError
	return errors.As(err, &insecure) || errors.As(err, &constraint)
}

// hasCounterSignature looks for a countersignature or RFC 3161 timestamp among
// the unauthenticated attributes.
func hasCounterSignature(attrs []byte) bool {
	rest := attrs
	for len(rest) > 0 {
		var attr struct {
			Type   asn1.ObjectIdentifier
			Values asn1.RawValue `asn1:"set"`
		}
		tail, err := asn1.Unmarshal(rest, &attr)
		if err != nil {
			return false
		}
		if attr.Type.Equal(oidCounterSig) || attr.Type.Equal(oidRFC3161) {
			return true
		}
		rest = tail
	}
	return false
}

// sameName compares a certificate issuer against a subject. DER bytes are the
// strict test; two encodings of one name (PrintableString vs UTF8String,
// attribute order) fall back to the parsed form.
func sameName(rawA []byte, a pkix.Name, rawB []byte, b pkix.Name) bool {
	if bytesEqual(rawA, rawB) {
		return true
	}
	return a.String() == b.String()
}

func serialHex(n *big.Int) string {
	if n == nil {
		return ""
	}
	b := n.Bytes()
	if len(b) == 0 {
		return "00"
	}
	return hex.EncodeToString(b)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// wellKnownVendors are names whose appearance on a *self-signed* signer
// certificate is impersonation, not identity. Matching is case-insensitive on
// the subject's common name / organisation.
var wellKnownVendors = []string{
	"microsoft", "google", "adobe", "oracle", "mozilla", "apple", "intel",
	"nvidia", "vmware", "cisco", "amazon", "dell", "hp inc", "hewlett",
	"lenovo", "symantec", "mcafee", "kaspersky", "avast", "sophos",
	"crowdstrike", "digicert", "sectigo", "globalsign", "comodo", "verisign",
}

// vendorNameIn returns the well-known vendor name found in subject, or "".
func vendorNameIn(subject string) string {
	s := strings.ToLower(subject)
	for _, v := range wellKnownVendors {
		if strings.Contains(s, v) {
			return v
		}
	}
	return ""
}
