package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Attestation: a signed statement of who the registrar accepted as a bot's
// owner. A compact JWS (RFC 7515), EdDSA over Ed25519, verifiable with the
// public key from GET /register/v1/keys (an RFC 8037 JWK).
const (
	attestTyp = "mm-agent-attestation+jwt"
	// ViaEnrollment: an enrollment token was used, so the owner was checked.
	ViaEnrollment = "enrollment"
	// ViaSecret: the shared secret was used; "responsible" is the caller's claim.
	ViaSecret = "secret"
)

// AttestClaims is the payload. Field order is the wire order.
type AttestClaims struct {
	BotID       string   `json:"bot_id"`
	Username    string   `json:"username"`
	Responsible string   `json:"responsible"`
	Trusted     []string `json:"trusted"`
	TrustedCut  int      `json:"trusted_cut,omitempty"`
	Kind        string   `json:"kind"`
	Via         string   `json:"via"`
	Iat         int64    `json:"iat"`
	Exp         int64    `json:"exp"`
}

// JWK is a public Ed25519 key as RFC 8037 describes it.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X   string `json:"x"`
}

// Attestor signs attestations. The private key never leaves it.
type Attestor struct {
	priv ed25519.PrivateKey
	kid  string
	TTL  time.Duration
}

var b64 = base64.RawURLEncoding

// ParseSeed reads a base64 or base64url (padding optional) 32-byte Ed25519
// seed. The error never contains the input.
func ParseSeed(v string) ([]byte, error) {
	v = strings.TrimRight(strings.TrimSpace(v), "=")
	raw, err := b64.DecodeString(v)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(v)
	}
	if err != nil || len(raw) != ed25519.SeedSize {
		return nil, errors.New("not base64 or base64url of a 32-byte Ed25519 seed")
	}
	return raw, nil
}

// NewAttestor builds an Attestor from a 32-byte seed.
func NewAttestor(seed []byte, ttl time.Duration) (*Attestor, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("seed must be 32 bytes")
	}
	if ttl <= 0 {
		return nil, errors.New("ttl must be positive")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Attestor{priv: priv, kid: Kid(priv.Public().(ed25519.PublicKey)), TTL: ttl}, nil
}

// Kid is the first 16 characters of base64url(sha256(raw public key)).
func Kid(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return b64.EncodeToString(h[:])[:16]
}

// Kid returns the key id.
func (a *Attestor) Kid() string { return a.kid }

// Key returns the public JWK.
func (a *Attestor) Key() JWK {
	pub := a.priv.Public().(ed25519.PublicKey)
	return JWK{Kty: "OKP", Crv: "Ed25519", Alg: "EdDSA", Use: "sig", Kid: a.kid, X: b64.EncodeToString(pub)}
}

// Sign stamps iat and exp (from now) on c and returns the compact JWS.
func (a *Attestor) Sign(c AttestClaims, now time.Time) (string, error) {
	c.Iat = now.Unix()
	c.Exp = now.Add(a.TTL).Unix()
	return a.SignExact(c)
}

// SignExact signs c as it is.
func (a *Attestor) SignExact(c AttestClaims) (string, error) {
	if c.Trusted == nil {
		c.Trusted = []string{}
	}
	return a.signJWS(attestTyp, c)
}

// signJWS signs claims as a compact JWS with header typ. Each record kind has
// its own typ, so a verifier of one kind never accepts another.
func (a *Attestor) signJWS(typ string, claims any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	header := `{"alg":"EdDSA","typ":"` + typ + `","kid":"` + a.kid + `"}`
	in := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString(payload)
	return in + "." + b64.EncodeToString(ed25519.Sign(a.priv, []byte(in))), nil
}

// VerifyAttestation checks the signature, header and expiry (at now) of token
// against pub and returns its claims.
func VerifyAttestation(token string, pub ed25519.PublicKey, now time.Time) (AttestClaims, error) {
	var c AttestClaims
	if err := verifyJWS(token, attestTyp, pub, &c); err != nil {
		return c, err
	}
	if now.Unix() >= c.Exp {
		return c, errors.New("expired")
	}
	return c, nil
}

// verifyJWS checks the header (exactly typ and pub's kid) and the signature
// of token, and decodes its payload into out.
func verifyJWS(token, typ string, pub ed25519.PublicKey, out any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("not a compact JWS")
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return errors.New("bad header encoding")
	}
	want := `{"alg":"EdDSA","typ":"` + typ + `","kid":"` + Kid(pub) + `"}`
	if subtle.ConstantTimeCompare(hb, []byte(want)) != 1 {
		return errors.New("unexpected header")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return errors.New("bad signature")
	}
	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return errors.New("bad payload encoding")
	}
	if err := json.Unmarshal(pb, out); err != nil {
		return fmt.Errorf("bad payload: %w", err)
	}
	return nil
}
