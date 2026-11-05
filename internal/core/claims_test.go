package core

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func claimService(t *testing.T) (*Service, *fakeProvider, ed25519.PublicKey) {
	t.Helper()
	f := newFake()
	s, _ := newService(t, f, "")
	a, err := NewAttestor(vectorSeed(), 30*24*time.Hour) // the registration's long TTL
	if err != nil {
		t.Fatal(err)
	}
	s.Attestor = a
	cs, err := OpenClaimStore(filepath.Join(t.TempDir(), "attestations.json"))
	if err != nil {
		t.Fatal(err)
	}
	s.Claims = cs
	return s, f, ed25519.NewKeyFromSeed(vectorSeed()).Public().(ed25519.PublicKey)
}

func TestAttestationRecordForBothWays(t *testing.T) {
	s, _, pub := claimService(t)
	ctx := context.Background()

	secretReg, err := s.Register(ctx, "shared", RegisterRequest{Name: "s-1", Responsible: "@Alice", Trusted: []string{"bob"}})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := mint(t, s, alice, "--kind autonomous")
	enrolled, err := register(s, tok, "name=e-1;trusted=bob")
	if err != nil {
		t.Fatal(err)
	}
	for name, reg := range map[string]Registration{"secret": secretReg, "enrollment": enrolled} {
		rec, err := s.AttestationRecord(ctx, reg.Agent.ID)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := VerifyAttestation(rec, pub, s.now())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want, err := VerifyAttestation(reg.Attestation, pub, s.now())
		if err != nil {
			t.Fatal(err)
		}
		// Same claims as the registration's, a fresh short expiry.
		if got.Exp-got.Iat != int64(AttestationTTL/time.Second) || got.Iat != s.now().Unix() {
			t.Fatalf("%s: iat/exp %d/%d", name, got.Iat, got.Exp)
		}
		got.Iat, got.Exp, want.Iat, want.Exp = 0, 0, 0, 0
		if got.BotID != want.BotID || got.Username != want.Username || got.Responsible != want.Responsible ||
			got.Kind != want.Kind || got.Via != want.Via || got.TrustedCut != want.TrustedCut ||
			len(got.Trusted) != len(want.Trusted) {
			t.Fatalf("%s: got %+v, registration had %+v", name, got, want)
		}
	}
	if c, _ := VerifyAttestation(mustRecord(t, s, secretReg.Agent.ID), pub, s.now()); c.Via != ViaSecret || c.Responsible != "alice" {
		t.Fatalf("secret claims: %+v", c)
	}
	if c, _ := VerifyAttestation(mustRecord(t, s, enrolled.Agent.ID), pub, s.now()); c.Via != ViaEnrollment || c.Kind != "autonomous" {
		t.Fatalf("enrollment claims: %+v", c)
	}
}

func mustRecord(t *testing.T, s *Service, id string) string {
	t.Helper()
	rec, err := s.AttestationRecord(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestAttestationRecordNone(t *testing.T) {
	s, f, _ := claimService(t)
	ctx := context.Background()
	for _, bad := range []string{"", "a/b", "../x", "x y", string(make([]byte, 65))} {
		if _, err := s.AttestationRecord(ctx, bad); !errors.Is(err, ErrBadRequest) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	if _, err := s.AttestationRecord(ctx, "unknown"); !errors.Is(err, ErrNoAttestation) {
		t.Fatalf("unknown: %v", err)
	}
	reg, _ := s.Register(ctx, "shared", RegisterRequest{Name: "s-2"})

	// Removed through the registrar: the claims go with the bot.
	if err := s.Unregister(ctx, "shared", "s-2"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Claims.Get(reg.Agent.ID); ok { // before any read could forget them
		t.Fatal("claims kept after unregister")
	}
	if _, err := s.AttestationRecord(ctx, reg.Agent.ID); !errors.Is(err, ErrNoAttestation) {
		t.Fatalf("after unregister: %v", err)
	}

	// Removed outside the registrar: the read finds it gone and forgets it.
	reg, _ = s.Register(ctx, "shared", RegisterRequest{Name: "s-3"})
	delete(f.agents, reg.Agent.Username)
	if _, err := s.AttestationRecord(ctx, reg.Agent.ID); !errors.Is(err, ErrNoAttestation) {
		t.Fatalf("bot gone: %v", err)
	}
	if _, ok := s.Claims.Get(reg.Agent.ID); ok {
		t.Fatal("claims kept for a bot that is gone")
	}

	// The username now belongs to another account: not this bot's claim.
	reg, _ = s.Register(ctx, "shared", RegisterRequest{Name: "s-4"})
	f.agents[reg.Agent.Username] = Agent{ID: "someone-else", Username: reg.Agent.Username}
	if _, err := s.AttestationRecord(ctx, reg.Agent.ID); !errors.Is(err, ErrNoAttestation) {
		t.Fatalf("username reused: %v", err)
	}

	// Without a key or a store there is nothing to read.
	reg, _ = s.Register(ctx, "shared", RegisterRequest{Name: "s-5"})
	s.Attestor = nil
	if _, err := s.AttestationRecord(ctx, reg.Agent.ID); !errors.Is(err, ErrNoAttestation) {
		t.Fatalf("no key: %v", err)
	}
	s.Claims = nil
	if _, err := s.AttestationRecord(ctx, reg.Agent.ID); !errors.Is(err, ErrNoAttestation) {
		t.Fatalf("no store: %v", err)
	}
}

func TestClaimStoreSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.json")
	st, _ := OpenClaimStore(path)
	if err := st.Put(ClaimRecord{BotID: "b1", Username: "u1", Via: ViaSecret, Kind: "session"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Put(ClaimRecord{BotID: "b2", Username: "u2", Via: ViaEnrollment, Kind: "session"}); err != nil {
		t.Fatal(err)
	}
	again, err := OpenClaimStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := again.Get("b1"); !ok || r.Username != "u1" {
		t.Fatalf("reload: %+v %v", r, ok)
	}
	if err := again.RemoveUsername("u2"); err != nil {
		t.Fatal(err)
	}
	if _, ok := again.Get("b2"); ok {
		t.Fatal("RemoveUsername kept the record")
	}
}
