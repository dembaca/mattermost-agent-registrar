package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// The release record (ADR-011 phase 3 of the agent bus): the registrar's
// operator names the SSH keys that sign the bus's release tags and, optionally,
// the version hosts should run. The registrar publishes both, installation
// wide, as a signed record. It is operator configuration: no command, nothing
// per team or channel. The hosts bound their trust in it themselves: they pin
// the keys on first contact and take an update only when it is newer, signed by
// a pinned key and not withdrawn.
const (
	releaseTyp = "mm-agent-release+jwt"
	// ReleaseTTL is the lifetime of a release record's signature. Records are
	// signed fresh for each request, so this only bounds how long a copy stays
	// valid.
	ReleaseTTL = time.Hour
)

// ReleaseSignerTypes are the SSH key types a release signer may have.
var ReleaseSignerTypes = []string{"ssh-ed25519", "sk-ssh-ed25519@openssh.com"}

var releaseVersionRE = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// ValidReleaseVersion says whether v is a release version: v<x.y.z>.
func ValidReleaseVersion(v string) bool { return releaseVersionRE.MatchString(v) }

// ReleaseClaims is the payload of a release record. Field order is the wire
// order.
type ReleaseClaims struct {
	Signers []string `json:"signers"`           // "<type> <base64>", in config order
	Version string   `json:"version,omitempty"` // v<x.y.z>; absent: the record names keys only
	SetAtMs int64    `json:"set_at_ms"`         // when the registrar started with this config, unix milliseconds
	Iat     int64    `json:"iat"`
	Exp     int64    `json:"exp"`
}

// Release is the operator's release setting.
type Release struct {
	Signers []string // "<type> <base64>", never empty
	Version string   // "" or v<x.y.z>
	SetAt   time.Time
}

// SignRelease stamps iat (now) and exp (now + ReleaseTTL) on c and returns the
// compact JWS.
func (a *Attestor) SignRelease(c ReleaseClaims, now time.Time) (string, error) {
	c.Iat = now.Unix()
	c.Exp = now.Add(ReleaseTTL).Unix()
	return a.SignReleaseExact(c)
}

// SignReleaseExact signs c as it is.
func (a *Attestor) SignReleaseExact(c ReleaseClaims) (string, error) {
	return a.signJWS(releaseTyp, c)
}

// VerifyRelease checks the signature, header (typ mm-agent-release+jwt) and
// expiry (at now) of a release record against pub and returns its claims.
func VerifyRelease(token string, pub ed25519.PublicKey, now time.Time) (ReleaseClaims, error) {
	var c ReleaseClaims
	if err := verifyJWS(token, releaseTyp, pub, &c); err != nil {
		return c, err
	}
	if now.Unix() >= c.Exp {
		return c, errors.New("expired")
	}
	return c, nil
}

// ReleaseRecord returns the signed release record, signed now. ErrNoRelease
// when the operator set none, or without an attestation key.
func (s *Service) ReleaseRecord() (string, error) {
	if s.Release == nil || s.Attestor == nil {
		return "", ErrNoRelease
	}
	return s.Attestor.SignRelease(ReleaseClaims{
		Signers: slices.Clone(s.Release.Signers),
		Version: s.Release.Version,
		SetAtMs: s.Release.SetAt.UnixMilli(),
	}, s.now())
}

// ParseReleaseSigners reads SSH public keys, one per line or comma-separated,
// in authorized_keys form. Blank lines and lines starting with # are skipped; a
// trailing comment after the key is dropped. Each key must be ssh-ed25519 or
// sk-ssh-ed25519@openssh.com with a well-formed key blob of that type. Returns
// "<type> <base64>" per key, in order. Errors name the entry by its number and
// never carry key material.
func ParseReleaseSigners(text string) ([]string, error) {
	var out []string
	n := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, entry := range strings.Split(line, ",") {
			f := strings.Fields(entry)
			if len(f) == 0 {
				continue
			}
			n++
			if len(f) < 2 {
				return nil, fmt.Errorf("key %d: not \"<type> <base64>\"", n)
			}
			if !slices.Contains(ReleaseSignerTypes, f[0]) {
				return nil, fmt.Errorf("key %d: type must be ssh-ed25519 or sk-ssh-ed25519@openssh.com", n)
			}
			if err := checkSSHBlob(f[0], f[1]); err != nil {
				return nil, fmt.Errorf("key %d: %v", n, err)
			}
			k := f[0] + " " + f[1]
			if slices.Contains(out, k) {
				return nil, fmt.Errorf("key %d: listed twice", n)
			}
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no key")
	}
	return out, nil
}

// checkSSHBlob checks that b64 is the SSH wire form of a key of type typ: the
// type string, a 32-byte Ed25519 key and, for a security key, its application.
func checkSSHBlob(typ, b64 string) error {
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return errors.New("key data is not base64")
	}
	next := func() ([]byte, bool) {
		if len(blob) < 4 {
			return nil, false
		}
		l := binary.BigEndian.Uint32(blob)
		if uint64(len(blob)-4) < uint64(l) {
			return nil, false
		}
		v := blob[4 : 4+l]
		blob = blob[4+l:]
		return v, true
	}
	t, ok := next()
	if !ok || string(t) != typ {
		return errors.New("key data does not match its type")
	}
	if k, ok := next(); !ok || len(k) != ed25519.PublicKeySize {
		return errors.New("key data is not an Ed25519 key")
	}
	if typ == "sk-ssh-ed25519@openssh.com" {
		if app, ok := next(); !ok || len(app) == 0 {
			return errors.New("key data has no application")
		}
	}
	if len(blob) != 0 {
		return errors.New("key data has trailing bytes")
	}
	return nil
}

// SignerFingerprint is the OpenSSH SHA256 fingerprint of a "<type> <base64>"
// key, as ssh-keygen -l shows it.
func SignerFingerprint(signer string) string {
	_, b, _ := strings.Cut(signer, " ")
	blob, _ := base64.StdEncoding.DecodeString(b)
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}
