package core

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	modeVectorHeader  = `{"alg":"EdDSA","typ":"mm-agent-mode+jwt","kid":"Vkdap1RjR0wChd9d"}`
	modeVectorPayload = `{"channel_id":"c0000000000000000000000000","mode":"coordinator","set_by":"alice","set_by_id":"u0000000000000000000000000","set_at_ms":1699999000000,"iat":1700000000,"exp":1700003600}`
	// modeVectorHash is the start of sha256(record) hex; the bus checks the same.
	modeVectorHash = "8663e8575e142e7c"
)

func modeVectorClaims() ModeClaims {
	return ModeClaims{ChannelID: "c0000000000000000000000000", Mode: ModeCoordinator, SetBy: "alice",
		SetByID: "u0000000000000000000000000", SetAtMs: 1699999000000, Iat: 1700000000, Exp: 1700003600}
}

func vectorPub() ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(vectorSeed()).Public().(ed25519.PublicKey)
}

func TestModeInteropVector(t *testing.T) {
	a, err := NewAttestor(vectorSeed(), 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if a.Kid() != vectorKid {
		t.Fatalf("kid %q", a.Kid())
	}
	pb, err := json.Marshal(modeVectorClaims())
	if err != nil || string(pb) != modeVectorPayload {
		t.Fatalf("payload:\n got  %s\n want %s", pb, modeVectorPayload)
	}
	tok, err := a.SignModeExact(modeVectorClaims())
	if err != nil {
		t.Fatal(err)
	}
	want := b64.EncodeToString([]byte(modeVectorHeader)) + "." + b64.EncodeToString([]byte(modeVectorPayload))
	if len(tok) <= len(want) || tok[:len(want)] != want {
		t.Fatal("header or payload segment differs from the vector")
	}
	sum := sha256.Sum256([]byte(tok))
	if got := hex.EncodeToString(sum[:])[:16]; got != modeVectorHash {
		t.Fatalf("record hash prefix %s", got)
	}
	c, err := VerifyMode(tok, vectorPub(), time.Unix(1700000000, 0))
	if err != nil || c != modeVectorClaims() {
		t.Fatalf("verify: %+v %v", c, err)
	}
	if _, err := VerifyMode(tok, vectorPub(), time.Unix(1700003600, 0)); err == nil {
		t.Fatal("expired record accepted")
	}
	bad := []byte(tok)
	bad[len(bad)-3] ^= 1
	if _, err := VerifyMode(string(bad), vectorPub(), time.Unix(1700000000, 0)); err == nil {
		t.Fatal("tampered record accepted")
	}
}

// Same key, different typ: neither record passes as the other.
func TestModeAndAttestationAreNotInterchangeable(t *testing.T) {
	a, _ := NewAttestor(vectorSeed(), time.Hour)
	mode, err := a.SignModeExact(modeVectorClaims())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAttestation(mode, vectorPub(), time.Unix(1700000000, 0)); err == nil {
		t.Fatal("mode record accepted as attestation")
	}
	att, err := a.SignExact(vectorClaims())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyMode(att, vectorPub(), time.Unix(1798761600, 0)); err == nil {
		t.Fatal("attestation accepted as mode record")
	}
}

func modeService(t *testing.T, path string) (*Service, *clock) {
	t.Helper()
	s, c := newService(t, newFake(), "")
	s.Store = nil // modes work without enrollment tokens
	a, _ := NewAttestor(vectorSeed(), 30*24*time.Hour)
	s.Attestor = a
	ms, err := OpenModeStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Modes = ms
	return s, c
}

func modeInv(h Human, channel, text string) Invocation {
	return Invocation{Human: h, Command: "/agent-mode", Text: text, ChannelID: channel}
}

var (
	hAlice = Human{ID: "u-alice", Handle: "alice"}
	hBob   = Human{ID: "u-bob", Handle: "bob"}
)

func TestModeCommand(t *testing.T) {
	s, c := modeService(t, "")
	ctx := context.Background()
	run := func(h Human, ch, text, want string) {
		t.Helper()
		if got := s.ModeCommand(ctx, modeInv(h, ch, text)); !strings.Contains(got, want) {
			t.Fatalf("%q in %s: %q, want %q", text, ch, got, want)
		}
	}
	run(hAlice, chanTeam, "", "not set (agents use their default, `direct` unless configured otherwise)")
	run(hAlice, chanTeam, "status", "not set")
	run(hAlice, chanTeam, "coordinator", "now `coordinator`")
	run(hBob, chanTeam, "STATUS", "`coordinator`, set by @alice on 2026-10-29 12:00 UTC")

	// The same mode again updates who set it and when.
	c.t = c.t.Add(time.Hour)
	run(hBob, chanTeam, "coordinator", "(was `coordinator`, set by @alice")
	m, ok := s.Modes.Get(chanTeam)
	if !ok || m.Mode != ModeCoordinator || m.SetBy != "bob" || m.SetByID != "u-bob" || !m.SetAt.Equal(c.t) {
		t.Fatalf("stored: %+v", m)
	}
	run(hAlice, chanTeam, "direct", "now `direct`")

	run(hAlice, chanTeam, "delegated", "not available yet (ADR-005 phase 3)")
	run(hAlice, chanTeam, "bogus", "/agent-mode coordinator")
	run(hAlice, chanTeam, "direct now", "/agent-mode status")
	run(hAlice, chanTeam, `"open`, "/agent-mode direct")

	// Only team channels, only members.
	run(hAlice, chanDM, "coordinator", "not in direct or group messages")
	run(hAlice, chanGroup, "status", "not in direct or group messages")
	run(hBob, chanPriv, "coordinator", "Only members of this channel")
	run(hBob, chanPriv, "status", "Only members of this channel")
	run(hAlice, chanNone, "direct", "not found")
	run(hAlice, "", "direct", "needs a channel")
	run(hAlice, "../etc", "direct", "needs a channel")
	for _, ch := range []string{chanDM, chanGroup, chanPriv, chanNone} {
		if _, ok := s.Modes.Get(ch); ok {
			t.Fatalf("mode stored for refused channel %s", ch)
		}
	}
	run(hAlice, chanPriv, "coordinator", "now `coordinator`")

	s.Attestor = nil
	run(hAlice, chanTeam, "status", "not enabled")
}

func TestModeRecord(t *testing.T) {
	s, _ := modeService(t, "")
	if _, err := s.ModeRecord("C0000000000000000000000000"); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("upper case id: %v", err)
	}
	if _, err := s.ModeRecord(chanTeam); !errors.Is(err, ErrNoMode) {
		t.Fatalf("unset: %v", err)
	}
	s.ModeCommand(context.Background(), modeInv(hAlice, chanTeam, "coordinator"))
	rec, err := s.ModeRecord(chanTeam)
	if err != nil {
		t.Fatal(err)
	}
	c, err := VerifyMode(rec, vectorPub(), s.now())
	want := ModeClaims{ChannelID: chanTeam, Mode: ModeCoordinator, SetBy: "alice", SetByID: "u-alice",
		SetAtMs: s.now().UnixMilli(), Iat: s.now().Unix(), Exp: s.now().Add(ModeTTL).Unix()}
	if err != nil || c != want {
		t.Fatalf("claims: %+v %v", c, err)
	}
}

func TestModeStorePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "modes.json")
	s, c := modeService(t, path)
	s.ModeCommand(context.Background(), modeInv(hAlice, chanTeam, "coordinator"))
	at := c.t
	c.t = c.t.Add(time.Minute)
	s.ModeCommand(context.Background(), modeInv(hAlice, chanPriv, "direct"))
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("store file: %v %v", fi, err)
	}
	re, err := OpenModeStore(path)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := re.Get(chanTeam)
	if !ok || m.Mode != ModeCoordinator || m.SetBy != "alice" || m.SetByID != "u-alice" || !m.SetAt.Equal(at) {
		t.Fatalf("reopened: %+v", m)
	}
	if m, ok := re.Get(chanPriv); !ok || m.Mode != ModeDirect {
		t.Fatalf("reopened private: %+v", m)
	}
	if _, ok := re.Get(chanDM); ok {
		t.Fatal("unexpected mode")
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenModeStore(path); err == nil {
		t.Fatal("corrupt store opened")
	}
	if s, err := OpenModeStore(filepath.Join(t.TempDir(), "none.json")); err != nil || s == nil {
		t.Fatalf("missing store: %v", err)
	}
}
