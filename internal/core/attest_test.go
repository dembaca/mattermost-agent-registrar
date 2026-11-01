package core

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"
	"time"
)

// The public interop seed 0x00..0x1f; not a credential.
func vectorSeed() []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

const (
	vectorKid     = "Vkdap1RjR0wChd9d"
	vectorHeader  = `{"alg":"EdDSA","typ":"mm-agent-attestation+jwt","kid":"Vkdap1RjR0wChd9d"}`
	vectorPayload = `{"bot_id":"abcdefghijklmnopqrstuvwxyz","username":"agent-test-abc123","responsible":"alice","trusted":["alice","bob"],"kind":"session","via":"enrollment","iat":1798761600,"exp":1801353600}`
)

func vectorClaims() AttestClaims {
	return AttestClaims{BotID: "abcdefghijklmnopqrstuvwxyz", Username: "agent-test-abc123", Responsible: "alice",
		Trusted: []string{"alice", "bob"}, Kind: "session", Via: ViaEnrollment, Iat: 1798761600, Exp: 1801353600}
}

func TestAttestationInteropVector(t *testing.T) {
	a, err := NewAttestor(vectorSeed(), 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if a.Kid() != vectorKid {
		t.Fatalf("kid %q", a.Kid())
	}
	pb, err := json.Marshal(vectorClaims())
	if err != nil || string(pb) != vectorPayload {
		t.Fatalf("payload:\n got  %s\n want %s", pb, vectorPayload)
	}
	tok, err := a.SignExact(vectorClaims())
	if err != nil {
		t.Fatal(err)
	}
	want := b64.EncodeToString([]byte(vectorHeader)) + "." + b64.EncodeToString([]byte(vectorPayload))
	if len(tok) <= len(want) || tok[:len(want)] != want {
		t.Fatal("header or payload segment differs from the vector")
	}
	sum := sha256.Sum256([]byte(tok))
	if got := hex.EncodeToString(sum[:])[:16]; got != "ac363c6df26b252b" {
		t.Fatalf("token hash prefix %s", got)
	}
	pub := ed25519.NewKeyFromSeed(vectorSeed()).Public().(ed25519.PublicKey)
	c, err := VerifyAttestation(tok, pub, time.Unix(1798761600, 0))
	if err != nil || c.Via != ViaEnrollment || c.Responsible != "alice" {
		t.Fatalf("verify: %v", err)
	}
	if _, err := VerifyAttestation(tok, pub, time.Unix(1801353600, 0)); err == nil {
		t.Fatal("expired token accepted")
	}
	bad := []byte(tok)
	bad[len(bad)-3] ^= 1
	if _, err := VerifyAttestation(string(bad), pub, time.Unix(1798761600, 0)); err == nil {
		t.Fatal("tampered token accepted")
	}
}

func TestParseSeedFormats(t *testing.T) {
	seed := vectorSeed()
	for _, in := range []string{
		b64.EncodeToString(seed),
		b64.EncodeToString(seed) + "=",
		" " + b64.EncodeToString(seed) + "\n",
		"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
	} {
		if got, err := ParseSeed(in); err != nil || string(got) != string(seed) {
			t.Fatalf("%q: %v", in, err)
		}
	}
	for _, in := range []string{"", "!!!", "AAEC"} {
		if _, err := ParseSeed(in); err == nil {
			t.Fatalf("%q accepted", in)
		}
	}
}

func TestRegisterAttestsEnrollmentAndSecret(t *testing.T) {
	f := newFake()
	svc, _ := newService(t, f, t.TempDir()+"/s.json")
	a, _ := NewAttestor(vectorSeed(), time.Hour)
	svc.Attestor = a
	pub := ed25519.NewKeyFromSeed(vectorSeed()).Public().(ed25519.PublicKey)

	reg, err := svc.Register(context.Background(), "shared", RegisterRequest{Name: "abc-1", Responsible: "@Alice"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := VerifyAttestation(reg.Attestation, pub, svc.now())
	if err != nil || c.Via != ViaSecret || c.Responsible != "alice" || c.Kind != "session" || c.BotID != reg.Agent.ID || c.Exp-c.Iat != 3600 {
		t.Fatalf("secret claims: %+v %v", c, err)
	}
	reg, err = svc.Register(context.Background(), "shared", RegisterRequest{Name: "abc-2"})
	if err != nil {
		t.Fatal(err)
	}
	if c, err = VerifyAttestation(reg.Attestation, pub, svc.now()); err != nil || c.Responsible != "" || c.Via != ViaSecret {
		t.Fatalf("secret without responsible: %+v %v", c, err)
	}

	svc.Attestor = nil
	if reg, err = svc.Register(context.Background(), "shared", RegisterRequest{Name: "abc-3"}); err != nil || reg.Attestation != "" {
		t.Fatalf("no key: %q %v", reg.Attestation, err)
	}
}

func TestEnrollmentAttestationMatchesDescription(t *testing.T) {
	f := newFake()
	s, _ := newService(t, f, "")
	a, _ := NewAttestor(vectorSeed(), time.Hour)
	s.Attestor = a
	sec, _ := mint(t, s, alice, "--kind autonomous")
	// Owner alice, token kind autonomous; "responsible" left out.
	reg, err := register(s, sec, "name=ops-1;trusted=alice,bob,ghost,alice,carol,dave,erin")
	if err != nil {
		t.Fatal(err)
	}
	pub := ed25519.NewKeyFromSeed(vectorSeed()).Public().(ed25519.PublicKey)
	c, err := VerifyAttestation(reg.Attestation, pub, s.now())
	if err != nil {
		t.Fatal(err)
	}
	if c.Via != ViaEnrollment || c.Responsible != "alice" || c.Kind != "autonomous" || c.TrustedCut != 2 ||
		!slices.Equal(c.Trusted, []string{"alice", "bob", "carol"}) || c.BotID != reg.Agent.ID || c.Username != reg.Agent.Username {
		t.Fatalf("claims: %+v", c)
	}
}
