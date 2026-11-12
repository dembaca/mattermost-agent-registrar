package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dembaca/mattermost-agent-registrar/internal/core"
	"github.com/dembaca/mattermost-agent-registrar/internal/mattermost"
)

func newDebugServer(t *testing.T, att *core.Attestor, debugTokens, mandateTokens []string) *server {
	t.Helper()
	mm := newFakeMM()
	mm.chanTypes = map[string]string{modeChan: "O", modeDM: "D"}
	mm.chanMembers = map[string]bool{modeChan + "/u-alice": true, modeDM + "/u-alice": true}
	ts := mm.server(t)
	cfg := config{
		publicChatURL:              "https://chat.example",
		rateLimitPerMin:            100,
		modeRateLimitPerMin:        100,
		mandateRateLimitPerMin:     100,
		debugRateLimitPerMin:       100,
		attestationRateLimitPerMin: 100,
		modeStore:                  filepath.Join(t.TempDir(), "modes.json"),
		mandateTokens:              mandateTokens,
		mandateStore:               filepath.Join(t.TempDir(), "mandates.json"),
		debugTokens:                debugTokens,
		debugStore:                 filepath.Join(t.TempDir(), "debug.json"),
		attestor:                   att,
		mm:                         mattermost.Config{URL: ts.URL, Token: "admin-pat", Team: "ai-agents", TokenDescription: "agent-registrar"},
	}
	cfg.policy.SharedSecret = "secret"
	s, err := newServer(cfg, ts.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func debugSlash(h http.Handler, token, userID, channelID, text string) *httptest.ResponseRecorder {
	form := url.Values{"token": {token}, "user_id": {userID}, "channel_id": {channelID}, "team_id": {"team-id"},
		"command": {"/agent-debug"}, "text": {text}}
	req := httptest.NewRequest(http.MethodPost, "/register/v1/debug", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func getDebug(h http.Handler, id string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/register/v1/debug/"+id, nil))
	return rr
}

func TestDebugCommandAndRecordOverHTTP(t *testing.T) {
	a, pub := testAttestor(t)
	s := newDebugServer(t, a, []string{"dbg-a", "dbg-b"}, nil)
	now := time.Now()
	s.svc.Now = func() time.Time { return now }
	h := s.routes()

	for _, tok := range []string{"", "wrong", "mand-a"} {
		if rr := debugSlash(h, tok, "u-alice", modeChan, "status"); rr.Code != http.StatusUnauthorized {
			t.Fatalf("token %q: %d", tok, rr.Code)
		}
	}
	if txt := ephemeral(t, debugSlash(h, "dbg-a", "b2", modeChan, "full")); !strings.Contains(txt, "no bots") {
		t.Fatalf("bot: %s", txt)
	}
	const none = `{"error":"no debug set"}`
	if rr := getDebug(h, modeChan); rr.Code != http.StatusNotFound || strings.TrimSpace(rr.Body.String()) != none ||
		rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unset: %d %s", rr.Code, rr.Body.String())
	}
	if txt := ephemeral(t, debugSlash(h, "dbg-a", "u-alice", modeChan, "")); !strings.Contains(txt, "off.") {
		t.Fatalf("status: %s", txt)
	}
	// Refused: a DM, a non-member, an unknown category, a too long end.
	if txt := ephemeral(t, debugSlash(h, "dbg-b", "u-alice", modeDM, "on wake")); !strings.Contains(txt, "direct or group") {
		t.Fatalf("DM: %s", txt)
	}
	if txt := ephemeral(t, debugSlash(h, "dbg-a", "u2", modeChan, "on wake")); !strings.Contains(txt, "Only members") {
		t.Fatalf("non-member: %s", txt)
	}
	if txt := ephemeral(t, debugSlash(h, "dbg-a", "u-alice", modeChan, "on wake costs")); !strings.Contains(txt, "Unknown debug category: `costs`") {
		t.Fatalf("unknown category: %s", txt)
	}
	if txt := ephemeral(t, debugSlash(h, "dbg-a", "u-alice", modeChan, "full for 48h")); !strings.Contains(txt, "at most 24h") {
		t.Fatalf("too long: %s", txt)
	}
	if rr := getDebug(h, modeChan); rr.Code != http.StatusNotFound {
		t.Fatalf("refused calls stored a setting: %d", rr.Code)
	}

	if txt := ephemeral(t, debugSlash(h, "dbg-b", "u-alice", modeChan, "On Wake PROPS for 2h")); !strings.Contains(txt, "`wake` `props`") {
		t.Fatalf("on: %s", txt)
	}
	rr := getDebug(h, modeChan)
	var body struct {
		Record string `json:"record"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || rr.Code != http.StatusOK || body.Record == "" ||
		rr.Header().Get("Content-Type") != "application/json" || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("get: %d %s", rr.Code, rr.Body.String())
	}
	hdr, _ := base64.RawURLEncoding.DecodeString(strings.Split(body.Record, ".")[0])
	if string(hdr) != `{"alg":"EdDSA","typ":"mm-agent-debug+jwt","kid":"`+a.Kid()+`"}` {
		t.Fatalf("header: %s", hdr)
	}
	c, err := core.VerifyDebug(body.Record, pub, now)
	want := core.DebugClaims{ChannelID: modeChan, Categories: []string{"wake", "props"}, SetBy: "dembaca", SetByID: "u-alice",
		SetAtMs: now.UnixMilli(), UntilMs: now.Add(2 * time.Hour).UnixMilli(), Iat: now.Unix(), Exp: now.Unix() + 3600}
	if err != nil || !reflect.DeepEqual(c, want) {
		t.Fatalf("claims: %+v %v", c, err)
	}
	if _, err := core.VerifyMode(body.Record, pub, now); err == nil {
		t.Fatal("debug record verifies as a mode record")
	}
	if _, err := core.VerifyMandate(body.Record, pub, now); err == nil {
		t.Fatal("debug record verifies as a mandate")
	}
	if _, err := core.VerifyAttestation(body.Record, pub, now); err == nil {
		t.Fatal("debug record verifies as an attestation")
	}

	// The end makes it 404, the same body as never set.
	now = now.Add(2 * time.Hour)
	if rr := getDebug(h, modeChan); rr.Code != http.StatusNotFound || strings.TrimSpace(rr.Body.String()) != none {
		t.Fatalf("ended: %d %s", rr.Code, rr.Body.String())
	}
	if txt := ephemeral(t, debugSlash(h, "dbg-a", "u-alice", modeChan, "full")); !strings.Contains(txt, "`wake` `identity` `sig` `asks` `calls` `props`") {
		t.Fatalf("full: %s", txt)
	}
	if rr := getDebug(h, modeChan); rr.Code != http.StatusOK {
		t.Fatalf("after full: %d", rr.Code)
	}
	if txt := ephemeral(t, debugSlash(h, "dbg-a", "u-alice", modeChan, "off")); !strings.Contains(txt, "off (was:") {
		t.Fatalf("off: %s", txt)
	}
	if rr := getDebug(h, modeChan); rr.Code != http.StatusNotFound || strings.TrimSpace(rr.Body.String()) != none {
		t.Fatalf("after off: %d %s", rr.Code, rr.Body.String())
	}

	for _, id := range []string{"short", "C0000000000000000000000000", "c00000000000000000000000000", "c000000000000000000000000_"} {
		if rr := getDebug(h, id); rr.Code != http.StatusBadRequest {
			t.Fatalf("%q: %d", id, rr.Code)
		}
	}
	// Nothing beyond the record: no key, no token in the reply.
	if strings.Contains(rr.Body.String(), "dbg-a") || strings.Contains(rr.Body.String(), "admin-pat") {
		t.Fatal("a token in the body")
	}
}

func TestDebugRecordHasItsOwnRateBucket(t *testing.T) {
	a, _ := testAttestor(t)
	s := newDebugServer(t, a, nil, nil)
	s.rate, s.mandateRate, s.debugRate = newLimiter(2), newLimiter(50), newLimiter(3)
	h := s.routes()
	for i := 0; i < 3; i++ {
		if rr := getDebug(h, modeChan); rr.Code != http.StatusNotFound {
			t.Fatalf("debug get %d: %d", i, rr.Code)
		}
	}
	if rr := getDebug(h, modeChan); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("debug bucket not enforced: %d", rr.Code)
	}
	if rr := getMandate(h, modeChan); rr.Code != http.StatusNotFound {
		t.Fatalf("mandate bucket drained by debug: %d", rr.Code)
	}
}

func TestDebugRoutesFollowConfig(t *testing.T) {
	a, _ := testAttestor(t)
	gone := func(rr *httptest.ResponseRecorder) bool {
		return rr.Code == http.StatusNotFound || rr.Code == http.StatusMethodNotAllowed
	}
	// No attestation key: neither route.
	h := newDebugServer(t, nil, nil, nil).routes()
	if rr := getDebug(h, modeChan); rr.Code != http.StatusNotFound || strings.Contains(rr.Body.String(), "no debug set") {
		t.Fatalf("GET without key: %d %s", rr.Code, rr.Body.String())
	}
	if !gone(debugSlash(h, "dbg-a", "u-alice", modeChan, "status")) {
		t.Fatal("command without key")
	}
	// Key without DEBUG_COMMAND_TOKEN: the GET only.
	h = newDebugServer(t, a, nil, nil).routes()
	if rr := getDebug(h, modeChan); rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "no debug set") {
		t.Fatalf("GET with key: %d %s", rr.Code, rr.Body.String())
	}
	if !gone(debugSlash(h, "dbg-a", "u-alice", modeChan, "status")) {
		t.Fatal("command without DEBUG_COMMAND_TOKEN")
	}
	// Next to the mandate command, each with its own token.
	h = newDebugServer(t, a, []string{"dbg-a"}, []string{"mand-a"}).routes()
	if rr := debugSlash(h, "mand-a", "u-alice", modeChan, "status"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("mandate token on the debug command: %d", rr.Code)
	}
	if rr := mandateSlash(h, "dbg-a", "u-alice", modeChan, "status"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("debug token on the mandate command: %d", rr.Code)
	}
	if txt := ephemeral(t, debugSlash(h, "dbg-a", "u-alice", modeChan, "status")); !strings.Contains(txt, "off.") {
		t.Fatalf("debug command next to mandate: %s", txt)
	}
}

func TestLoadConfigDebugCommand(t *testing.T) {
	seed := base64.RawURLEncoding.EncodeToString(testSeed())
	load := func(extra map[string]string) (config, error) {
		env := map[string]string{"MATTERMOST_URL": "http://mm", "MATTERMOST_TOKEN": "pat", "REGISTRATION_SECRET": "s"}
		for k, v := range extra {
			env[k] = v
		}
		return loadConfig(func(k string) string { return env[k] })
	}
	_, err := load(map[string]string{"DEBUG_COMMAND_TOKEN": "d"})
	if err == nil || !strings.Contains(err.Error(), "DEBUG_COMMAND_TOKEN needs ATTESTATION_KEY") {
		t.Fatalf("debug without key: %v", err)
	}
	cfg, err := load(map[string]string{"DEBUG_COMMAND_TOKEN": "d1, d2", "ATTESTATION_KEY": seed})
	if err != nil || strings.Join(cfg.debugTokens, "|") != "d1|d2" || cfg.debugStore != "/data/debug.json" ||
		cfg.debugRateLimitPerMin != 120 || len(cfg.mandateTokens) != 0 || len(cfg.mm.CommandTokens) != 0 {
		t.Fatalf("debug with key: %+v %v", cfg.debugTokens, err)
	}
	cfg, err = load(map[string]string{"DEBUG_COMMAND_TOKEN": "d", "ATTESTATION_KEY": seed, "DEBUG_STORE": "/x/d.json"})
	if err != nil || cfg.debugStore != "/x/d.json" {
		t.Fatalf("debug store: %v", err)
	}
}
