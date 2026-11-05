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
	"strings"
	"testing"
	"time"

	"github.com/dembaca/mattermost-agent-registrar/internal/core"
	"github.com/dembaca/mattermost-agent-registrar/internal/mattermost"
)

const mandateHome = "h0000000000000000000000000" // the channel ~home in team-m

func newMandateServer(t *testing.T, att *core.Attestor, mandateTokens, modeTokens []string) *server {
	t.Helper()
	mm := newFakeMM()
	mm.chanTypes = map[string]string{modeChan: "O", modeDM: "D"}
	mm.chanMembers = map[string]bool{modeChan + "/u-alice": true, modeDM + "/u-alice": true}
	mm.chanNames = map[string]string{"home": mandateHome}
	ts := mm.server(t)
	cfg := config{
		publicChatURL:          "https://chat.example",
		rateLimitPerMin:        100,
		modeRateLimitPerMin:    100,
		mandateRateLimitPerMin: 100,
		modeTokens:             modeTokens,
		modeStore:              filepath.Join(t.TempDir(), "modes.json"),
		mandateTokens:          mandateTokens,
		mandateStore:           filepath.Join(t.TempDir(), "mandates.json"),
		attestor:               att,
		mm:                     mattermost.Config{URL: ts.URL, Token: "admin-pat", Team: "ai-agents", TokenDescription: "agent-registrar"},
	}
	cfg.policy.SharedSecret = "secret"
	s, err := newServer(cfg, ts.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mandateSlash(h http.Handler, token, userID, channelID, text string) *httptest.ResponseRecorder {
	form := url.Values{"token": {token}, "user_id": {userID}, "channel_id": {channelID}, "team_id": {"team-m"},
		"command": {"/agent-mandate"}, "text": {text}}
	req := httptest.NewRequest(http.MethodPost, "/register/v1/mandate", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func getMandate(h http.Handler, id string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/register/v1/mandates/"+id, nil))
	return rr
}

func TestMandateCommandAndRecordOverHTTP(t *testing.T) {
	a, pub := testAttestor(t)
	h := newMandateServer(t, a, []string{"mand-a", "mand-b"}, nil).routes()

	for _, tok := range []string{"", "wrong", "mode-a"} {
		if rr := mandateSlash(h, tok, "u-alice", modeChan, "status"); rr.Code != http.StatusUnauthorized {
			t.Fatalf("token %q: %d", tok, rr.Code)
		}
	}
	if txt := ephemeral(t, mandateSlash(h, "mand-a", "b2", modeChan, "status")); !strings.Contains(txt, "no bots") {
		t.Fatalf("bot: %s", txt)
	}
	if rr := getMandate(h, modeChan); rr.Code != http.StatusNotFound || strings.TrimSpace(rr.Body.String()) != `{"error":"no mandate set"}` {
		t.Fatalf("unset: %d %s", rr.Code, rr.Body.String())
	}
	if txt := ephemeral(t, mandateSlash(h, "mand-a", "u-alice", modeChan, "")); !strings.Contains(txt, "not set") {
		t.Fatalf("status: %s", txt)
	}
	if txt := ephemeral(t, mandateSlash(h, "mand-b", "u-alice", modeDM, "👑 of ~home")); !strings.Contains(txt, "direct or group") {
		t.Fatalf("DM: %s", txt)
	}
	if txt := ephemeral(t, mandateSlash(h, "mand-a", "u2", modeChan, "👑 of ~home")); !strings.Contains(txt, "Only members") {
		t.Fatalf("non-member: %s", txt)
	}
	if txt := ephemeral(t, mandateSlash(h, "mand-a", "u-alice", modeChan, "👑 of ~nowhere")); txt != "Channel ~nowhere does not exist." {
		t.Fatalf("unknown home: %s", txt)
	}
	if txt := ephemeral(t, mandateSlash(h, "mand-a", "u-alice", modeChan, "please")); !strings.Contains(txt, "/agent-mandate off") {
		t.Fatalf("help: %s", txt)
	}
	if rr := getMandate(h, modeChan); rr.Code != http.StatusNotFound {
		t.Fatalf("refused calls stored a mandate: %d", rr.Code)
	}

	until := time.Now().UTC().AddDate(0, 0, 3).Format("2006-01-02")
	before := time.Now()
	if txt := ephemeral(t, mandateSlash(h, "mand-b", "u-alice", modeChan, ":crown: Of ~home UNTIL "+until+" follow the plan")); !strings.Contains(txt, "Mandate set") {
		t.Fatalf("set: %s", txt)
	}
	rr := getMandate(h, modeChan)
	var body struct {
		Record string `json:"record"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || rr.Code != http.StatusOK || body.Record == "" ||
		rr.Header().Get("Content-Type") != "application/json" || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("get: %d", rr.Code)
	}
	c, err := core.VerifyMandate(body.Record, pub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if c.ChannelID != modeChan || c.CrownOf != mandateHome || c.SetBy != "dembaca" || c.SetByID != "u-alice" ||
		c.Until != until || c.Note != "follow the plan" ||
		c.SetAtMs < before.UnixMilli() || c.SetAtMs > time.Now().UnixMilli() || c.Exp-c.Iat != 3600 {
		t.Fatalf("claims: %+v", c)
	}
	if _, err := core.VerifyMode(body.Record, pub, time.Now()); err == nil {
		t.Fatal("mandate record verifies as a mode record")
	}
	if _, err := core.VerifyAttestation(body.Record, pub, time.Now()); err == nil {
		t.Fatal("mandate record verifies as an attestation")
	}
	if txt := ephemeral(t, mandateSlash(h, "mand-a", "u-alice", modeChan, "status")); !strings.Contains(txt, "~home") || !strings.Contains(txt, "set by @dembaca") {
		t.Fatalf("status after set: %s", txt)
	}
	if txt := ephemeral(t, mandateSlash(h, "mand-a", "u-alice", modeChan, "off")); !strings.Contains(txt, "Mandate removed") {
		t.Fatalf("off: %s", txt)
	}
	if rr := getMandate(h, modeChan); rr.Code != http.StatusNotFound {
		t.Fatalf("after off: %d", rr.Code)
	}

	for _, id := range []string{"short", "C0000000000000000000000000", "c00000000000000000000000000", "c000000000000000000000000_"} {
		if rr := getMandate(h, id); rr.Code != http.StatusBadRequest {
			t.Fatalf("%q: %d", id, rr.Code)
		}
	}
}

func TestMandateRecordHasItsOwnRateBucket(t *testing.T) {
	a, _ := testAttestor(t)
	s := newMandateServer(t, a, nil, nil)
	s.rate, s.modeRate, s.mandateRate = newLimiter(2), newLimiter(50), newLimiter(3)
	h := s.routes()
	for i := 0; i < 3; i++ {
		if rr := getMandate(h, modeChan); rr.Code != http.StatusNotFound {
			t.Fatalf("mandate get %d: %d", i, rr.Code)
		}
	}
	if rr := getMandate(h, modeChan); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("mandate bucket not enforced: %d", rr.Code)
	}
	// The mode and the main bucket are untouched.
	if rr := getMode(h, modeChan); rr.Code != http.StatusNotFound {
		t.Fatalf("mode bucket drained by mandates: %d", rr.Code)
	}
	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/register/v1/keys", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("keys %d: %d", i, rr.Code)
		}
	}
}

func TestMandateRoutesFollowConfig(t *testing.T) {
	a, _ := testAttestor(t)
	gone := func(rr *httptest.ResponseRecorder) bool {
		return rr.Code == http.StatusNotFound || rr.Code == http.StatusMethodNotAllowed
	}
	// No attestation key: neither route.
	h := newMandateServer(t, nil, nil, nil).routes()
	if rr := getMandate(h, modeChan); rr.Code != http.StatusNotFound || strings.Contains(rr.Body.String(), "no mandate set") {
		t.Fatalf("GET without key: %d %s", rr.Code, rr.Body.String())
	}
	if !gone(mandateSlash(h, "mand-a", "u-alice", modeChan, "status")) {
		t.Fatal("command without key")
	}
	// Key without MANDATE_COMMAND_TOKEN: the GET only.
	h = newMandateServer(t, a, nil, nil).routes()
	if rr := getMandate(h, modeChan); rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "no mandate set") {
		t.Fatalf("GET with key: %d %s", rr.Code, rr.Body.String())
	}
	if !gone(mandateSlash(h, "mand-a", "u-alice", modeChan, "status")) {
		t.Fatal("command without MANDATE_COMMAND_TOKEN")
	}
	// Both commands side by side, each with its own token.
	h = newMandateServer(t, a, []string{"mand-a"}, []string{"mode-a"}).routes()
	if rr := mandateSlash(h, "mode-a", "u-alice", modeChan, "status"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("mode token on the mandate command: %d", rr.Code)
	}
	if rr := modeSlash(h, "mand-a", "u-alice", modeChan, "status"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("mandate token on the mode command: %d", rr.Code)
	}
	if txt := ephemeral(t, mandateSlash(h, "mand-a", "u-alice", modeChan, "status")); !strings.Contains(txt, "not set") {
		t.Fatalf("mandate command next to mode: %s", txt)
	}
	if txt := ephemeral(t, modeSlash(h, "mode-a", "u-alice", modeChan, "status")); !strings.Contains(txt, "not set") {
		t.Fatalf("mode command next to mandate: %s", txt)
	}
}

func TestLoadConfigMandateCommand(t *testing.T) {
	seed := base64.RawURLEncoding.EncodeToString(testSeed())
	load := func(extra map[string]string) (config, error) {
		env := map[string]string{"MATTERMOST_URL": "http://mm", "MATTERMOST_TOKEN": "pat", "REGISTRATION_SECRET": "s"}
		for k, v := range extra {
			env[k] = v
		}
		return loadConfig(func(k string) string { return env[k] })
	}
	_, err := load(map[string]string{"MANDATE_COMMAND_TOKEN": "m"})
	if err == nil || !strings.Contains(err.Error(), "MANDATE_COMMAND_TOKEN needs ATTESTATION_KEY") {
		t.Fatalf("mandate without key: %v", err)
	}
	cfg, err := load(map[string]string{"MANDATE_COMMAND_TOKEN": "m1, m2", "ATTESTATION_KEY": seed})
	if err != nil || strings.Join(cfg.mandateTokens, "|") != "m1|m2" || cfg.mandateStore != "/data/mandates.json" ||
		cfg.mandateRateLimitPerMin != 120 || len(cfg.modeTokens) != 0 || len(cfg.mm.CommandTokens) != 0 {
		t.Fatalf("mandate with key: %+v %v", cfg.mandateTokens, err)
	}
	cfg, err = load(map[string]string{"MANDATE_COMMAND_TOKEN": "m", "ATTESTATION_KEY": seed, "MANDATE_STORE": "/x/m.json"})
	if err != nil || cfg.mandateStore != "/x/m.json" {
		t.Fatalf("mandate store: %v", err)
	}
	if cfg, err := load(nil); err != nil || len(cfg.mandateTokens) != 0 {
		t.Fatalf("no mandate command: %v", err)
	}
}
