package core

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	mandateVectorHeader  = `{"alg":"EdDSA","typ":"mm-agent-mandate+jwt","kid":"Vkdap1RjR0wChd9d"}`
	mandateVectorPayload = `{"channel_id":"c0000000000000000000000000","crown_of":"c1111111111111111111111111","set_by":"alice","set_by_id":"u0000000000000000000000000","set_at_ms":1699999000000,"until":"2023-12-01","note":"ship it","iat":1700000000,"exp":1700003600}`
)

func mandateVectorClaims() MandateClaims {
	return MandateClaims{ChannelID: "c0000000000000000000000000", CrownOf: "c1111111111111111111111111", SetBy: "alice",
		SetByID: "u0000000000000000000000000", SetAtMs: 1699999000000, Until: "2023-12-01", Note: "ship it", Iat: 1700000000, Exp: 1700003600}
}

func TestMandateSignVerify(t *testing.T) {
	a, _ := NewAttestor(vectorSeed(), 30*24*time.Hour)
	pb, err := json.Marshal(mandateVectorClaims())
	if err != nil || string(pb) != mandateVectorPayload {
		t.Fatalf("payload:\n got  %s\n want %s", pb, mandateVectorPayload)
	}
	tok, err := a.SignMandateExact(mandateVectorClaims())
	if err != nil {
		t.Fatal(err)
	}
	want := b64.EncodeToString([]byte(mandateVectorHeader)) + "." + b64.EncodeToString([]byte(mandateVectorPayload))
	if len(tok) <= len(want) || tok[:len(want)] != want {
		t.Fatal("header or payload segment differs")
	}
	c, err := VerifyMandate(tok, vectorPub(), time.Unix(1700000000, 0))
	if err != nil || c != mandateVectorClaims() {
		t.Fatalf("verify: %+v %v", c, err)
	}
	if _, err := VerifyMandate(tok, vectorPub(), time.Unix(1700003600, 0)); err == nil {
		t.Fatal("expired record accepted")
	}
	bad := []byte(tok)
	bad[len(bad)-3] ^= 1
	if _, err := VerifyMandate(string(bad), vectorPub(), time.Unix(1700000000, 0)); err == nil {
		t.Fatal("tampered record accepted")
	}
	other := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	if _, err := VerifyMandate(tok, other, time.Unix(1700000000, 0)); err == nil {
		t.Fatal("wrong key accepted")
	}
	// Empty until and note stay on the wire as empty strings.
	empty := mandateVectorClaims()
	empty.Until, empty.Note = "", ""
	pb, _ = json.Marshal(empty)
	if !strings.Contains(string(pb), `"until":"","note":"","iat"`) {
		t.Fatalf("empty fields: %s", pb)
	}
}

// Same key, different typ: no record passes as another kind.
func TestMandateAndOtherRecordsAreNotInterchangeable(t *testing.T) {
	a, _ := NewAttestor(vectorSeed(), time.Hour)
	now := time.Unix(1700000000, 0)
	mandate, _ := a.SignMandateExact(mandateVectorClaims())
	mode, _ := a.SignModeExact(modeVectorClaims())
	att, _ := a.SignExact(vectorClaims())
	if _, err := VerifyMode(mandate, vectorPub(), now); err == nil {
		t.Fatal("mandate accepted as mode record")
	}
	if _, err := VerifyAttestation(mandate, vectorPub(), now); err == nil {
		t.Fatal("mandate accepted as attestation")
	}
	if _, err := VerifyMandate(mode, vectorPub(), now); err == nil {
		t.Fatal("mode record accepted as mandate")
	}
	if _, err := VerifyMandate(att, vectorPub(), time.Unix(1798761600, 0)); err == nil {
		t.Fatal("attestation accepted as mandate")
	}
	// A wrong typ with a valid signature.
	wrong, err := a.signJWS("mm-agent-other+jwt", mandateVectorClaims())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyMandate(wrong, vectorPub(), now); err == nil {
		t.Fatal("wrong typ accepted")
	}
}

func mandateService(t *testing.T, path string) (*Service, *clock) {
	t.Helper()
	s, c := modeService(t, "")
	ms, err := OpenMandateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Mandates = ms
	return s, c
}

func mandateInv(h Human, channel, text string) Invocation {
	return Invocation{Human: h, Command: "/agent-mandate", Text: text, ChannelID: channel, TeamID: teamID}
}

func TestParseMandate(t *testing.T) {
	today := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	long := strings.Repeat("x", MandateNoteMax)
	for _, c := range []struct {
		in   string
		want mandateRequest
	}{
		{"", mandateRequest{action: "status"}},
		{"  STATUS ", mandateRequest{action: "status"}},
		{"off", mandateRequest{action: "off"}},
		{"OFF", mandateRequest{action: "off"}},
		{"👑 of ~proj-home", mandateRequest{action: "set", home: "proj-home"}},
		{"👑 of proj-home", mandateRequest{action: "set", home: "proj-home"}},
		{":crown: OF ~Proj-Home", mandateRequest{action: "set", home: "proj-home"}},
		{":CROWN: of ~h", mandateRequest{action: "set", home: "h"}},
		{"👑 of ~h until 2026-10-29", mandateRequest{action: "set", home: "h", until: "2026-10-29"}},
		{"👑 of ~h UNTIL 2026-11-28", mandateRequest{action: "set", home: "h", until: "2026-11-28"}},
		{"👑 of ~h until 2026-11-05 focus on  the API", mandateRequest{action: "set", home: "h", until: "2026-11-05", note: "focus on  the API"}},
		{"👑 of ~h focus on the API", mandateRequest{action: "set", home: "h", note: "focus on the API"}},
		{"👑 of ~h " + long, mandateRequest{action: "set", home: "h", note: long}},
	} {
		got, refusal := parseMandate(c.in, today)
		if refusal != "" || got != c.want {
			t.Errorf("%q: %+v %q, want %+v", c.in, got, refusal, c.want)
		}
	}
	for _, c := range []struct{ in, refusal string }{
		{"👑 of ~h until", "needs a date"},
		{"👑 of ~h  until later", "not a valid date"},
		{"👑 of ~h until 2026-02-30", "not a valid date"},
		{"👑 of ~h until 29.10.2026", "not a valid date"},
		{"👑 of ~h until 2026-10-28", "in the past"},
		{"👑 of ~h until 2026-11-29", "more than 30 days"},
		{"👑 of ~h " + long + "x", "too long"},
		{"👑 of ~h line one\nline two", "one line"},
		{"👑 of ~h until 2026-11-05 a\r\nb", "one line"},
	} {
		if _, refusal := parseMandate(c.in, today); !strings.Contains(refusal, c.refusal) {
			t.Errorf("%q: refusal %q, want %q", c.in, refusal, c.refusal)
		}
	}
	// Usage (empty refusal, empty action).
	for _, in := range []string{"bogus", "👑", "👑 of", "👑 for ~h", "of ~h", "off now", "status now", "👑 of ~", "👑 of ~bad!name", "crown of ~h"} {
		if got, refusal := parseMandate(in, today); got.action != "" || refusal != "" {
			t.Errorf("%q: %+v %q, want usage", in, got, refusal)
		}
	}
	// The note limit counts characters, not bytes.
	if _, refusal := parseMandate("👑 of ~h "+strings.Repeat("ä", MandateNoteMax), today); refusal != "" {
		t.Errorf("200 two-byte characters refused: %q", refusal)
	}
}

func TestMandateCommand(t *testing.T) {
	s, c := mandateService(t, "")
	ctx := context.Background()
	run := func(h Human, ch, text, want string) {
		t.Helper()
		if got := s.MandateCommand(ctx, mandateInv(h, ch, text)); !strings.Contains(got, want) {
			t.Fatalf("%q in %s: %q, want %q", text, ch, got, want)
		}
	}
	run(hAlice, chanTeam, "", "not set")
	run(hAlice, chanTeam, "off", "has no mandate")
	run(hAlice, chanTeam, "👑 of ~proj-home", "Mandate set: the 👑 of ~proj-home")
	m, ok := s.Mandates.Get(chanTeam)
	if !ok || m.ChannelID != chanTeam || m.CrownOf != chanPriv || m.SetBy != "alice" || m.SetByID != "u-alice" ||
		!m.SetAt.Equal(c.t) || m.Until != "" || m.Note != "" {
		t.Fatalf("stored: %+v", m)
	}
	run(hBob, chanTeam, "STATUS", "the 👑 of ~proj-home gives tasks and priorities here, set by @alice on 2026-10-29 12:00 UTC, no end date")

	// A new command replaces it, with until and note.
	c.t = c.t.Add(time.Hour)
	run(hBob, chanTeam, ":crown: of ~team-home until 2026-11-10 ship 0.6", "until 2026-11-10 (replaces: the 👑 of ~proj-home")
	m, _ = s.Mandates.Get(chanTeam)
	if m.CrownOf != chanTeam || m.SetBy != "bob" || m.Until != "2026-11-10" || m.Note != "ship 0.6" {
		t.Fatalf("replaced: %+v", m)
	}
	run(hAlice, chanTeam, "status", "until 2026-11-10. Note: ship 0.6")
	// Today is allowed, 30 days is the limit.
	run(hAlice, chanTeam, "👑 of ~proj-home until 2026-10-29", "until 2026-10-29")
	run(hAlice, chanTeam, "👑 of ~proj-home until 2026-11-28", "until 2026-11-28")
	run(hAlice, chanTeam, "👑 of ~proj-home until 2026-11-29", "more than 30 days")
	run(hAlice, chanTeam, "👑 of ~proj-home until 2026-10-28", "in the past")
	run(hAlice, chanTeam, "👑 of ~proj-home until 2026-02-30", "not a valid date")
	if m, _ := s.Mandates.Get(chanTeam); m.Until != "2026-11-28" {
		t.Fatalf("refused commands changed the mandate: %+v", m)
	}

	// Unknown home, also in another team: nothing is stored.
	run(hAlice, chanPriv, "👑 of ~nowhere", "~nowhere is not a channel you are a member of (or it does not exist)")
	run(hAlice, chanPriv, "👑 of ~elsewhere", "~elsewhere is not a channel you are a member of (or it does not exist)")
	if _, ok := s.Mandates.Get(chanPriv); ok {
		t.Fatal("mandate stored for an unknown home")
	}
	run(hAlice, chanPriv, "bogus", "/agent-mandate off")
	run(hAlice, chanPriv, "👑 of ~proj-home until soon", "not a valid date")
	run(hAlice, chanPriv, "👑 of ~proj-home "+strings.Repeat("x", 201), "too long")
	inv := mandateInv(hAlice, chanPriv, "👑 of ~proj-home")
	inv.TeamID = ""
	if got := s.MandateCommand(ctx, inv); !strings.Contains(got, "needs a team") {
		t.Fatalf("no team: %q", got)
	}

	// The home must be one the human is a member of: a private channel's id is
	// not published for a stranger.
	run(hBob, chanTeam, "👑 of ~proj-home", "~proj-home is not a channel you are a member of (or it does not exist)")
	// A private channel and a missing one are answered alike, word for word.
	if a, b := s.MandateCommand(ctx, mandateInv(hBob, chanTeam, "👑 of ~proj-home")),
		s.MandateCommand(ctx, mandateInv(hBob, chanTeam, "👑 of ~nowhere")); strings.ReplaceAll(a, "proj-home", "x") != strings.ReplaceAll(b, "nowhere", "x") {
		t.Fatalf("private and missing answered differently: %q vs %q", a, b)
	}
	if m, _ := s.Mandates.Get(chanTeam); m.SetBy != "alice" {
		t.Fatalf("a refused naming changed the mandate: %+v", m)
	}

	// Only team channels, only members.
	run(hAlice, chanDM, "👑 of ~proj-home", "not in direct or group messages")
	run(hAlice, chanGroup, "status", "not in direct or group messages")
	run(hBob, chanPriv, "👑 of ~proj-home", "Only members of this channel")
	run(hBob, chanPriv, "status", "Only members of this channel")
	run(hBob, chanPriv, "off", "Only members of this channel")
	run(hAlice, chanNone, "off", "not found")
	run(hAlice, "", "status", "needs a channel")
	run(hAlice, "../etc", "status", "needs a channel")
	for _, ch := range []string{chanDM, chanGroup, chanPriv, chanNone} {
		if _, ok := s.Mandates.Get(ch); ok {
			t.Fatalf("mandate stored for refused channel %s", ch)
		}
	}

	// off removes it; the other channel keeps its own.
	run(hAlice, chanPriv, "👑 of ~team-home", "Mandate set")
	run(hAlice, chanTeam, "off", "Mandate removed: the 👑 of ~proj-home")
	run(hAlice, chanTeam, "status", "not set")
	run(hAlice, chanTeam, "off", "has no mandate")
	if _, ok := s.Mandates.Get(chanPriv); !ok {
		t.Fatal("off removed another channel's mandate")
	}

	s.Attestor = nil
	run(hAlice, chanTeam, "status", "not enabled")
}

func TestMandateRecord(t *testing.T) {
	s, _ := mandateService(t, "")
	if _, err := s.MandateRecord("C0000000000000000000000000"); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("upper case id: %v", err)
	}
	if _, err := s.MandateRecord(chanTeam); !errors.Is(err, ErrNoMandate) {
		t.Fatalf("unset: %v", err)
	}
	s.MandateCommand(context.Background(), mandateInv(hAlice, chanTeam, "👑 of ~proj-home until 2026-11-10 hello"))
	rec, err := s.MandateRecord(chanTeam)
	if err != nil {
		t.Fatal(err)
	}
	c, err := VerifyMandate(rec, vectorPub(), s.now())
	want := MandateClaims{ChannelID: chanTeam, CrownOf: chanPriv, SetBy: "alice", SetByID: "u-alice",
		SetAtMs: s.now().UnixMilli(), Until: "2026-11-10", Note: "hello", Iat: s.now().Unix(), Exp: s.now().Add(MandateTTL).Unix()}
	if err != nil || c != want {
		t.Fatalf("claims: %+v %v", c, err)
	}
	s.MandateCommand(context.Background(), mandateInv(hAlice, chanTeam, "off"))
	if _, err := s.MandateRecord(chanTeam); !errors.Is(err, ErrNoMandate) {
		t.Fatalf("after off: %v", err)
	}
	s.Mandates = nil
	if _, err := s.MandateRecord(chanTeam); !errors.Is(err, ErrNoMandate) {
		t.Fatalf("store off: %v", err)
	}
}

func TestMandateStorePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mandates.json")
	s, c := mandateService(t, path)
	ctx := context.Background()
	s.MandateCommand(ctx, mandateInv(hAlice, chanTeam, "👑 of ~proj-home until 2026-11-10 note"))
	at := c.t
	s.MandateCommand(ctx, mandateInv(hAlice, chanPriv, "👑 of ~team-home"))
	s.MandateCommand(ctx, mandateInv(hAlice, chanPriv, "off"))
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("store file: %v %v", fi, err)
	}
	re, err := OpenMandateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := re.Get(chanTeam)
	if !ok || m.CrownOf != chanPriv || m.Home != "proj-home" || m.SetBy != "alice" || m.SetByID != "u-alice" ||
		!m.SetAt.Equal(at) || m.Until != "2026-11-10" || m.Note != "note" {
		t.Fatalf("reopened: %+v", m)
	}
	if _, ok := re.Get(chanPriv); ok {
		t.Fatal("deleted mandate came back")
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenMandateStore(path); err == nil {
		t.Fatal("corrupt store opened")
	}
	if s, err := OpenMandateStore(filepath.Join(t.TempDir(), "none.json")); err != nil || s == nil {
		t.Fatalf("missing store: %v", err)
	}
}
