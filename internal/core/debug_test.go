package core

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	debugVectorHeader  = `{"alg":"EdDSA","typ":"mm-agent-debug+jwt","kid":"Vkdap1RjR0wChd9d"}`
	debugVectorPayload = `{"channel_id":"c0000000000000000000000000","categories":["wake","sig"],"set_by":"alice","set_by_id":"u0000000000000000000000000","set_at_ms":1699999000000,"until_ms":1700002600000,"iat":1700000000,"exp":1700003600}`
)

func debugVectorClaims() DebugClaims {
	return DebugClaims{ChannelID: "c0000000000000000000000000", Categories: []string{"wake", "sig"}, SetBy: "alice",
		SetByID: "u0000000000000000000000000", SetAtMs: 1699999000000, UntilMs: 1700002600000, Iat: 1700000000, Exp: 1700003600}
}

func TestDebugSignVerify(t *testing.T) {
	a, _ := NewAttestor(vectorSeed(), 30*24*time.Hour)
	pb, err := json.Marshal(debugVectorClaims())
	if err != nil || string(pb) != debugVectorPayload {
		t.Fatalf("payload:\n got  %s\n want %s", pb, debugVectorPayload)
	}
	tok, err := a.SignDebugExact(debugVectorClaims())
	if err != nil {
		t.Fatal(err)
	}
	want := b64.EncodeToString([]byte(debugVectorHeader)) + "." + b64.EncodeToString([]byte(debugVectorPayload))
	if len(tok) <= len(want) || tok[:len(want)] != want {
		t.Fatal("header or payload segment differs")
	}
	c, err := VerifyDebug(tok, vectorPub(), time.Unix(1700000000, 0))
	if err != nil || !reflect.DeepEqual(c, debugVectorClaims()) {
		t.Fatalf("verify: %+v %v", c, err)
	}
	if _, err := VerifyDebug(tok, vectorPub(), time.Unix(1700003600, 0)); err == nil {
		t.Fatal("expired record accepted")
	}
	bad := []byte(tok)
	bad[len(bad)-3] ^= 1
	if _, err := VerifyDebug(string(bad), vectorPub(), time.Unix(1700000000, 0)); err == nil {
		t.Fatal("tampered record accepted")
	}
	// SignDebug: exp is the signature's freshness, an hour, whatever until_ms says.
	now := time.Unix(1700000000, 0)
	tok, _ = a.SignDebug(DebugClaims{ChannelID: "c0000000000000000000000000", Categories: []string{"wake"}, UntilMs: now.Add(24 * time.Hour).UnixMilli()}, now)
	if c, err := VerifyDebug(tok, vectorPub(), now); err != nil || c.Iat != now.Unix() || c.Exp != now.Unix()+3600 {
		t.Fatalf("SignDebug: %+v %v", c, err)
	}
}

// Same key, different typ: no record passes as another kind.
func TestDebugAndOtherRecordsAreNotInterchangeable(t *testing.T) {
	a, _ := NewAttestor(vectorSeed(), time.Hour)
	now := time.Unix(1700000000, 0)
	debug, _ := a.SignDebugExact(debugVectorClaims())
	mode, _ := a.SignModeExact(modeVectorClaims())
	mandate, _ := a.SignMandateExact(mandateVectorClaims())
	if _, err := VerifyMode(debug, vectorPub(), now); err == nil {
		t.Fatal("debug accepted as mode record")
	}
	if _, err := VerifyMandate(debug, vectorPub(), now); err == nil {
		t.Fatal("debug accepted as mandate")
	}
	if _, err := VerifyAttestation(debug, vectorPub(), now); err == nil {
		t.Fatal("debug accepted as attestation")
	}
	if _, err := VerifyDebug(mode, vectorPub(), now); err == nil {
		t.Fatal("mode record accepted as debug")
	}
	if _, err := VerifyDebug(mandate, vectorPub(), now); err == nil {
		t.Fatal("mandate accepted as debug")
	}
}

func TestParseDebug(t *testing.T) {
	all := DebugCategories
	for _, c := range []struct {
		in   string
		want debugRequest
	}{
		{"", debugRequest{action: "status"}},
		{"  STATUS ", debugRequest{action: "status", dur: DebugDefault}},
		{"off", debugRequest{action: "off", dur: DebugDefault}},
		{"on wake", debugRequest{action: "on", categories: []string{"wake"}, dur: DebugDefault}},
		// Canonical order, duplicates folded, any case.
		{"On PROPS wake props", debugRequest{action: "on", categories: []string{"wake", "props"}, dur: DebugDefault}},
		{"off sig asks", debugRequest{action: "off", categories: []string{"sig", "asks"}, dur: DebugDefault}},
		{"set calls for 2h", debugRequest{action: "set", categories: []string{"calls"}, dur: 2 * time.Hour}},
		{"set identity for 1h30m", debugRequest{action: "set", categories: []string{"identity"}, dur: 90 * time.Minute}},
		{"on full", debugRequest{action: "on", categories: all, dur: DebugDefault}},
		{"full", debugRequest{action: "full", categories: all, dur: DebugDefault}},
		{"full for 24h", debugRequest{action: "full", categories: all, dur: 24 * time.Hour}},
		{"full for 1d", debugRequest{action: "full", categories: all, dur: 24 * time.Hour}},
		{"on wake for 1m", debugRequest{action: "on", categories: []string{"wake"}, dur: time.Minute}},
		{"off wake for 30m", debugRequest{action: "off", categories: []string{"wake"}, dur: 30 * time.Minute}},
	} {
		got, refusal := parseDebug(c.in)
		if refusal != "" || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: %+v %q, want %+v", c.in, got, refusal, c.want)
		}
	}
	for _, c := range []struct{ in, refusal string }{
		{"on wake delegation", "Unknown debug category: `delegation`. Known: `wake` `identity` `sig` `asks` `calls` `props`, or `full` for all."},
		{"set costs context", "Unknown debug categories: `costs`, `context`"},
		{"on", "`on` needs at least one category"},
		{"set for 2h", "`set` needs at least one category"},
		{"full wake", "`full` takes no categories"},
		{"off for 2h", "`for` does not apply"},
		{"on wake for 25h", "out of range: at least 1m, at most 24h"},
		{"on wake for 2d", "out of range"},
		{"on wake for 30s", "out of range"},
		{"on wake for -1h", "out of range"},
		{"on wake for soon", "`soon` is not a duration"},
		{"on wake for", "`for` comes last"},
		{"on for 2h wake", "`for` comes last"},
		{"on wake for 2h for 3h", "`for` comes last"},
	} {
		if _, refusal := parseDebug(c.in); !strings.Contains(refusal, c.refusal) {
			t.Errorf("%q: refusal %q, want %q", c.in, refusal, c.refusal)
		}
	}
	// Usage (empty refusal, empty action).
	for _, in := range []string{"bogus", "wake", "enable wake", "status now", "status for 2h", "for 2h", ":bug: on"} {
		if got, refusal := parseDebug(in); got.action != "" || refusal != "" {
			t.Errorf("%q: %+v %q, want usage", in, got, refusal)
		}
	}
}

func debugService(t *testing.T, path string) (*Service, *clock) {
	t.Helper()
	s, c := modeService(t, "")
	ds, err := OpenDebugStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Debug = ds
	return s, c
}

func debugInv(h Human, channel, text string) Invocation {
	return Invocation{Human: h, Command: "/agent-debug", Text: text, ChannelID: channel, TeamID: teamID}
}

func TestDebugCommand(t *testing.T) {
	s, c := debugService(t, "")
	ctx := context.Background()
	t0 := c.t
	run := func(h Human, ch, text, want string) {
		t.Helper()
		if got := s.DebugCommand(ctx, debugInv(h, ch, text)); !strings.Contains(got, want) {
			t.Fatalf("%q in %s: %q, want %q", text, ch, got, want)
		}
	}
	state := func(cats []string, until time.Time, by string) {
		t.Helper()
		d, ok := s.Debug.Get(chanTeam)
		if !ok || !reflect.DeepEqual(d.Categories, cats) || !d.Until.Equal(until) || d.SetBy != by || !d.SetAt.Equal(c.t) {
			t.Fatalf("stored: %+v %v, want %v until %v by %s", d, ok, cats, until, by)
		}
	}
	run(hAlice, chanTeam, "", "Debug in this channel: off.")
	run(hAlice, chanTeam, "off", "off (it was not on)")
	if _, ok := s.Debug.Get(chanTeam); ok {
		t.Fatal("off stored something")
	}

	// Default end: an hour.
	run(hAlice, chanTeam, "on wake", "Debug in this channel: `wake`, until 2026-10-29 13:00 UTC (1h from now), set by @alice")
	state([]string{"wake"}, t0.Add(time.Hour), "alice")

	// on adds, and the setting gets one new end; built from the previous record.
	c.t = t0.Add(10 * time.Minute)
	run(hBob, chanTeam, "on sig props", "`wake` `sig` `props`, until 2026-10-29 13:10 UTC (1h from now), set by @bob (was: `wake`, until 2026-10-29 13:00 UTC)")
	state([]string{"wake", "sig", "props"}, c.t.Add(time.Hour), "bob")

	// off removes only what it names, and also sets a new end (for applies).
	c.t = t0.Add(20 * time.Minute)
	run(hAlice, chanTeam, "off sig for 3h", "`wake` `props`, until 2026-10-29 15:20 UTC (3h from now)")
	state([]string{"wake", "props"}, c.t.Add(3*time.Hour), "alice")
	run(hAlice, chanTeam, "status", "`wake` `props`, until 2026-10-29 15:20 UTC (3h from now), set by @alice")
	// A category that is not on: nothing removed, a new end all the same.
	run(hAlice, chanTeam, "off asks", "`wake` `props`, until 2026-10-29 13:20 UTC")
	state([]string{"wake", "props"}, c.t.Add(time.Hour), "alice")

	// set replaces.
	run(hAlice, chanTeam, "set calls asks", "`asks` `calls`, until")
	state([]string{"asks", "calls"}, c.t.Add(time.Hour), "alice")

	// full turns all on; at most 24 h.
	run(hAlice, chanTeam, "full for 24h", "`wake` `identity` `sig` `asks` `calls` `props`, until 2026-10-30 12:20 UTC (24h from now)")
	state(DebugCategories, c.t.Add(24*time.Hour), "alice")
	run(hAlice, chanTeam, "full for 25h", "out of range")
	run(hAlice, chanTeam, "on wake for 2d", "out of range")
	// Unknown categories are refused; nothing changes.
	run(hAlice, chanTeam, "set wake delegation", "Unknown debug category: `delegation`")
	run(hAlice, chanTeam, "on", "needs at least one category")
	run(hAlice, chanTeam, "bogus", "/agent-debug set <category…>")
	state(DebugCategories, c.t.Add(24*time.Hour), "alice")

	// off with every category named ends it like off alone.
	run(hAlice, chanTeam, "off full", "Debug in this channel: off (was: `wake` `identity`")
	if _, ok := s.Debug.Get(chanTeam); ok {
		t.Fatal("empty setting kept")
	}
	run(hAlice, chanTeam, "set wake sig", "`wake` `sig`")
	run(hAlice, chanTeam, "off", "Debug in this channel: off (was: `wake` `sig`")
	run(hAlice, chanTeam, "status", "Debug in this channel: off.")

	// An ended setting counts as off: the next command starts from nothing.
	run(hAlice, chanTeam, "on wake identity for 30m", "`wake` `identity`")
	c.t = c.t.Add(30 * time.Minute)
	run(hAlice, chanTeam, "status", "Debug in this channel: off.")
	run(hBob, chanTeam, "on asks", "Debug in this channel: `asks`, until")
	if got := s.DebugCommand(ctx, debugInv(hBob, chanTeam, "status")); strings.Contains(got, "was:") || strings.Contains(got, "wake") {
		t.Fatalf("ended categories came back: %q", got)
	}
	state([]string{"asks"}, c.t.Add(time.Hour), "bob")
	c.t = c.t.Add(2 * time.Hour)
	run(hAlice, chanTeam, "off", "off (it was not on)")
	if _, ok := s.Debug.Get(chanTeam); ok {
		t.Fatal("off kept an ended setting")
	}

	// Only team channels, only members (active humans; bots and guests are
	// refused by the adapter before this).
	run(hAlice, chanDM, "on wake", "not in direct or group messages")
	run(hAlice, chanGroup, "status", "not in direct or group messages")
	run(hBob, chanPriv, "on wake", "Only members of this channel can see or switch its debug setting.")
	run(hBob, chanPriv, "status", "Only members of this channel")
	run(hBob, chanPriv, "off", "Only members of this channel")
	run(hAlice, chanNone, "on wake", "not found")
	run(hAlice, "", "status", "needs a channel")
	for _, ch := range []string{chanDM, chanGroup, chanPriv, chanNone} {
		if _, ok := s.Debug.Get(ch); ok {
			t.Fatalf("debug stored for refused channel %s", ch)
		}
	}

	// Each channel has its own setting.
	run(hAlice, chanPriv, "full", "`wake`")
	run(hAlice, chanTeam, "status", "off.")

	s.Attestor = nil
	run(hAlice, chanTeam, "status", "not enabled")
}

func TestDebugRecord(t *testing.T) {
	s, c := debugService(t, "")
	ctx := context.Background()
	if _, err := s.DebugRecord("C0000000000000000000000000"); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("upper case id: %v", err)
	}
	if _, err := s.DebugRecord(chanTeam); !errors.Is(err, ErrNoDebug) {
		t.Fatalf("unset: %v", err)
	}
	s.DebugCommand(ctx, debugInv(hAlice, chanTeam, "on props wake for 2h"))
	set := c.t
	c.t = c.t.Add(5 * time.Minute)
	rec, err := s.DebugRecord(chanTeam)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyDebug(rec, vectorPub(), c.t)
	want := DebugClaims{ChannelID: chanTeam, Categories: []string{"wake", "props"}, SetBy: "alice", SetByID: "u-alice",
		SetAtMs: set.UnixMilli(), UntilMs: set.Add(2 * time.Hour).UnixMilli(), Iat: c.t.Unix(), Exp: c.t.Add(DebugTTL).Unix()}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("claims: %+v %v\nwant %+v", got, err, want)
	}
	// Rebuilt from the previous record: bob's command keeps alice's categories.
	s.DebugCommand(ctx, debugInv(hBob, chanTeam, "on sig"))
	rec, _ = s.DebugRecord(chanTeam)
	got, _ = VerifyDebug(rec, vectorPub(), c.t)
	if !reflect.DeepEqual(got.Categories, []string{"wake", "sig", "props"}) || got.SetBy != "bob" || got.SetByID != "u-bob" ||
		got.SetAtMs != c.t.UnixMilli() || got.UntilMs != c.t.Add(time.Hour).UnixMilli() {
		t.Fatalf("rebuilt: %+v", got)
	}
	// Still there a moment before its end, gone at it.
	c.t = c.t.Add(time.Hour - time.Millisecond)
	if _, err := s.DebugRecord(chanTeam); err != nil {
		t.Fatalf("before the end: %v", err)
	}
	c.t = c.t.Add(time.Millisecond)
	if _, err := s.DebugRecord(chanTeam); !errors.Is(err, ErrNoDebug) {
		t.Fatalf("ended: %v", err)
	}
	s.DebugCommand(ctx, debugInv(hAlice, chanTeam, "full"))
	s.DebugCommand(ctx, debugInv(hAlice, chanTeam, "off"))
	if _, err := s.DebugRecord(chanTeam); !errors.Is(err, ErrNoDebug) {
		t.Fatalf("after off: %v", err)
	}
	s.Debug = nil
	if _, err := s.DebugRecord(chanTeam); !errors.Is(err, ErrNoDebug) {
		t.Fatalf("store off: %v", err)
	}
}

func TestDebugStorePersistsAndPrunes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "debug.json")
	s, c := debugService(t, path)
	ctx := context.Background()
	s.DebugCommand(ctx, debugInv(hAlice, chanTeam, "on wake sig for 3h"))
	at := c.t
	s.DebugCommand(ctx, debugInv(hAlice, chanPriv, "full for 30m"))
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("store file: %v %v", fi, err)
	}
	re, err := OpenDebugStore(path)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := re.Get(chanTeam)
	if !ok || !reflect.DeepEqual(d.Categories, []string{"wake", "sig"}) || d.SetBy != "alice" || d.SetByID != "u-alice" ||
		!d.SetAt.Equal(at) || !d.Until.Equal(at.Add(3*time.Hour)) {
		t.Fatalf("reopened: %+v", d)
	}
	// The sweep drops the ended setting only, on disk too.
	c.t = c.t.Add(time.Hour)
	s.PruneDebug()
	if _, ok := s.Debug.Get(chanPriv); ok {
		t.Fatal("ended setting not pruned")
	}
	re, _ = OpenDebugStore(path)
	if _, ok := re.Get(chanPriv); ok {
		t.Fatal("pruned setting still on disk")
	}
	if _, ok := re.Get(chanTeam); !ok {
		t.Fatal("prune dropped a running setting")
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDebugStore(path); err == nil {
		t.Fatal("corrupt store opened")
	}
	if s, err := OpenDebugStore(filepath.Join(t.TempDir(), "none.json")); err != nil || s == nil {
		t.Fatalf("missing store: %v", err)
	}
}
