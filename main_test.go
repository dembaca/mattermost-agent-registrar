package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dembaca/mattermost-agent-registrar/internal/core"
	"github.com/dembaca/mattermost-agent-registrar/internal/mattermost"
)

func TestEnvBool(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	if !envBool(get, "B", true) {
		t.Fatalf("empty env: want default true")
	}
	for _, v := range []string{"true", "TRUE", "1", "yes", "on"} {
		env["B"] = v
		if !envBool(get, "B", false) {
			t.Fatalf("%q: want true", v)
		}
	}
	for _, v := range []string{"false", "FALSE", "0", "no", "off"} {
		env["B"] = v
		if envBool(get, "B", true) {
			t.Fatalf("%q: want false", v)
		}
	}
	env["B"] = "maybe"
	if !envBool(get, "B", true) {
		t.Fatalf("unknown value: want default true")
	}
}

func TestLoadConfig(t *testing.T) {
	base := map[string]string{"MATTERMOST_URL": "http://mm:8065/", "MATTERMOST_TOKEN": "pat", "REGISTRATION_SECRET": "s"}
	load := func(extra map[string]string) (config, error) {
		env := map[string]string{}
		for k, v := range base {
			env[k] = v
		}
		for k, v := range extra {
			env[k] = v
		}
		return loadConfig(func(k string) string { return env[k] })
	}
	cfg, err := load(nil)
	if err != nil || cfg.policy.SharedSecret != "s" || cfg.mm.URL != "http://mm:8065" || len(cfg.mm.CommandTokens) != 0 {
		t.Fatalf("base: %+v %v", cfg, err)
	}
	cfg, err = load(map[string]string{"BOT_USERNAME_PREFIX": "ai-", "DEFAULT_TEAM_NAME": "t", "DEFAULT_CHANNEL_NAME": "c"})
	if err != nil || cfg.policy.BotPrefix != "ai-" || cfg.mm.Team != "t" || cfg.policy.DefaultChannel != "c" {
		t.Fatalf("names: %+v %v", cfg, err)
	}
	if _, err := load(map[string]string{"ALLOW_SHARED_SECRET": "false"}); err == nil || !strings.Contains(err.Error(), "no way to register") {
		t.Fatalf("no credential type: %v", err)
	}
	if _, err := load(map[string]string{"SLASH_COMMAND_TOKEN": "x", "ENROLLMENT_PEPPER": "short"}); err == nil || !strings.Contains(err.Error(), "ENROLLMENT_PEPPER") {
		t.Fatalf("short pepper: %v", err)
	}
	cfg, err = load(map[string]string{"ALLOW_SHARED_SECRET": "off", "SLASH_COMMAND_TOKEN": "a, b",
		"ENROLLMENT_PEPPER": strings.Repeat("p", 32), "ENROLLMENT_MAX_TTL": "14d", "ENROLLMENT_DEFAULT_TTL": "7d"})
	if err != nil || cfg.policy.SharedSecret != "" || strings.Join(cfg.mm.CommandTokens, "|") != "a|b" {
		t.Fatalf("enrollment only: %+v %v", cfg, err)
	}
	if _, err := load(map[string]string{"SLASH_COMMAND_TOKEN": "x", "ENROLLMENT_PEPPER": strings.Repeat("p", 32), "ENROLLMENT_MAX_TTL": "7d"}); err == nil {
		t.Fatal("default TTL above max accepted")
	}
	if cfg, err := load(nil); err != nil || cfg.policy.TokenRetention != 30*24*time.Hour {
		t.Fatalf("default retention: %v %v", cfg.policy.TokenRetention, err)
	}
	if cfg, err := load(map[string]string{"ENROLLMENT_RETENTION": "0"}); err != nil || cfg.policy.TokenRetention != 0 {
		t.Fatalf("retention 0: %v %v", cfg.policy.TokenRetention, err)
	}
	if cfg, err := load(map[string]string{"ENROLLMENT_RETENTION": "2w"}); err != nil || cfg.policy.TokenRetention != 14*24*time.Hour {
		t.Fatalf("retention 2w: %v %v", cfg.policy.TokenRetention, err)
	}
	if _, err := load(map[string]string{"ENROLLMENT_RETENTION": "soon"}); err == nil || !strings.Contains(err.Error(), "ENROLLMENT_RETENTION") {
		t.Fatalf("bad retention: %v", err)
	}
}

// fakeMM is a minimal Mattermost API for the HTTP-level tests.
type fakeMM struct {
	mu          sync.Mutex
	users       map[string]mattermost.User // by username
	descs       map[string]string          // bot username -> description
	assigned    map[string]string          // bot id -> owner id
	prefsFail   bool
	channelType string
	chanTypes   map[string]string // channel id -> type, for GET /api/v4/channels/{id}
	chanMembers map[string]bool   // "channel id/user id"
	chanNames   map[string]string // channel name -> id in team "team-m", for the mandate command
}

func (f *fakeMM) server(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	byID := func(id string) (mattermost.User, bool) {
		for _, u := range f.users {
			if u.ID == id {
				return u, true
			}
		}
		return mattermost.User{}, false
	}
	mux.HandleFunc("GET /api/v4/users/username/{name}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		u, ok := f.users[r.PathValue("name")]
		if !ok {
			http.NotFound(w, nil)
			return
		}
		_ = json.NewEncoder(w).Encode(u)
	})
	mux.HandleFunc("GET /api/v4/users/me", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(mattermost.User{ID: "admin-id"})
	})
	mux.HandleFunc("GET /api/v4/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		u, ok := byID(r.PathValue("id"))
		if !ok {
			http.NotFound(w, nil)
			return
		}
		_ = json.NewEncoder(w).Encode(u)
	})
	mux.HandleFunc("PUT /api/v4/users/me/preferences", func(w http.ResponseWriter, _ *http.Request) {
		if f.prefsFail {
			http.Error(w, "nope", http.StatusBadRequest)
		}
	})
	mux.HandleFunc("POST /api/v4/bots", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.descs[body["username"]] = body["description"]
		id := "id-" + body["username"]
		f.users[body["username"]] = mattermost.User{ID: id, Username: body["username"], IsBot: true}
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(mattermost.Bot{UserID: id, Username: body["username"]})
	})
	mux.HandleFunc("POST /api/v4/bots/{bot}/disable", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		for name, u := range f.users {
			if u.ID == r.PathValue("bot") {
				delete(f.users, name)
			}
		}
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("POST /api/v4/bots/{bot}/assign/{owner}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.assigned[r.PathValue("bot")] = r.PathValue("owner")
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("POST /api/v4/users/{id}/tokens", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mattermost.AccessToken{Token: "bot-token-" + r.PathValue("id"), ID: "tok-id"})
	})
	mux.HandleFunc("GET /api/v4/teams/name/{team}", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"team-id"}`))
	})
	mux.HandleFunc("POST /api/v4/teams/team-id/members", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("GET /api/v4/teams/team-id/members/{uid}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("uid") != "u-alice" {
			http.NotFound(w, nil)
			return
		}
		_, _ = w.Write([]byte(`{"delete_at":0}`))
	})
	mux.HandleFunc("GET /api/v4/teams/team-id/channels/name/{ch}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"ch-` + r.PathValue("ch") + `","type":"` + f.channelType + `"}`))
	})
	mux.HandleFunc("GET /api/v4/teams/team-m/channels/name/{ch}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		id, ok := f.chanNames[r.PathValue("ch")]
		if !ok {
			http.NotFound(w, nil)
			return
		}
		_, _ = w.Write([]byte(`{"id":"` + id + `","type":"O"}`))
	})
	mux.HandleFunc("GET /api/v4/channels/{ch}/members/{uid}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.chanMembers[r.PathValue("ch")+"/"+r.PathValue("uid")] {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		http.NotFound(w, nil) // otherwise nobody is a channel member; public channels still pass
	})
	mux.HandleFunc("GET /api/v4/channels/{ch}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		typ, ok := f.chanTypes[r.PathValue("ch")]
		if !ok {
			http.NotFound(w, nil)
			return
		}
		_, _ = w.Write([]byte(`{"id":"` + r.PathValue("ch") + `","type":"` + typ + `"}`))
	})
	mux.HandleFunc("POST /api/v4/channels/{ch}/members", func(http.ResponseWriter, *http.Request) {})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func newTestServer(t *testing.T, mm *fakeMM, enroll bool) *server {
	t.Helper()
	return newAttestingServer(t, mm, enroll, nil)
}

func newAttestingServer(t *testing.T, mm *fakeMM, enroll bool, att *core.Attestor) *server {
	t.Helper()
	ts := mm.server(t)
	cfg := config{
		publicChatURL:   "https://chat.example",
		rateLimitPerMin: 100,
		mm: mattermost.Config{URL: ts.URL, Token: "admin-pat", Team: "ai-agents", HideBotDM: true,
			TokenDescription: "agent-registrar"},
	}
	cfg.attestor = att
	cfg.policy.BotPrefix = "agent-"
	cfg.policy.DefaultChannel = "agents"
	cfg.policy.SharedSecret = "secret"
	cfg.policy.MaxTrusted = 10
	if enroll {
		cfg.mm.CommandTokens = []string{"cmd-token"}
		cfg.pepper = strings.Repeat("p", 32)
		cfg.enrollStore = filepath.Join(t.TempDir(), "enrollments.json")
		c, err := loadConfig(func(k string) string {
			return map[string]string{"MATTERMOST_URL": "x", "MATTERMOST_TOKEN": "x", "REGISTRATION_SECRET": "x"}[k]
		})
		if err != nil {
			t.Fatal(err)
		}
		cfg.policy.DefaultTTL, cfg.policy.MaxTTL = c.policy.DefaultTTL, c.policy.MaxTTL
		cfg.policy.DefaultMaxBots, cfg.policy.MaxBotsLimit, cfg.policy.MaxTokensPerUser = 3, 20, 20
	}
	s, err := newServer(cfg, ts.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newFakeMM() *fakeMM {
	return &fakeMM{
		users: map[string]mattermost.User{
			"dembaca":  {ID: "u-alice", Username: "dembaca"},
			"kollegin": {ID: "u2", Username: "kollegin"},
			"agent-x":  {ID: "b1", Username: "agent-x", IsBot: true},
			"helper":   {ID: "b2", Username: "helper", IsBot: true},
		},
		descs:       map[string]string{},
		assigned:    map[string]string{},
		channelType: "O",
	}
}

func post(h http.Handler, path, auth, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestRegisterSucceedsWhenHideDMFails(t *testing.T) {
	mm := newFakeMM()
	mm.prefsFail = true
	h := newTestServer(t, mm, false).routes()
	rr := post(h, "/register/v1/agents", "secret", `{"name":"cursor-1","display_name":"Cursor 1"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d body %s", rr.Code, rr.Body.String())
	}
	var resp registerResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.BotToken != "bot-token-id-agent-cursor-1" || resp.UserID != "id-agent-cursor-1" || resp.URL != "https://chat.example" || resp.Owner != "" {
		t.Fatalf("unexpected resp: %+v", resp)
	}
}

func TestSharedSecretWritesAnUnboundDescription(t *testing.T) {
	mm := newFakeMM()
	h := newTestServer(t, mm, false).routes()
	for body, want := range map[string]string{
		`{"name":"vtpm-1","responsible":"@Dembaca","trusted":["dembaca","kollegin","agent-x","ghost","dembaca"],"kind":"session"}`: "unbound · claims @dembaca · trusts @dembaca, @kollegin · via agent-registrar",
		`{"name":"ops-1","responsible":"dembaca","kind":"autonomous"}`:                                                             "unbound · claims @dembaca · autonomous · via agent-registrar",
		`{"name":"plain-1"}`: "unbound · via agent-registrar",
	} {
		rr := post(h, "/register/v1/agents", "secret", body)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", body, rr.Code, rr.Body.String())
		}
		var name struct{ Name string }
		_ = json.Unmarshal([]byte(body), &name)
		if got := mm.descs["agent-"+name.Name]; got != want {
			t.Fatalf("description:\n got  %q\n want %q", got, want)
		}
	}
	if len(mm.assigned) != 0 {
		t.Fatalf("shared secret called assign_bot: %v", mm.assigned)
	}
	if rr := post(h, "/register/v1/agents", "wrong", `{"name":"x-1"}`); rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: %d", rr.Code)
	}
}

func slash(h http.Handler, token, userID, text string) *httptest.ResponseRecorder {
	form := url.Values{"token": {token}, "user_id": {userID}, "command": {"/agent-token"}, "text": {text}}
	req := httptest.NewRequest(http.MethodPost, "/register/v1/command", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestSlashCommandMintsATokenThatBindsTheOwner(t *testing.T) {
	mm := newFakeMM()
	h := newTestServer(t, mm, true).routes()

	if rr := slash(h, "wrong", "u-alice", "create"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong command token: %d %s", rr.Code, rr.Body.String())
	}
	// A bot can execute slash commands through the API; it gets no token.
	rr := slash(h, "cmd-token", "b2", "create")
	if !strings.Contains(rr.Body.String(), "no bots") || strings.Contains(rr.Body.String(), "mmenr_") {
		t.Fatalf("bot: %s", rr.Body.String())
	}

	rr = slash(h, "cmd-token", "u-alice", "create --kind autonomous --label ci")
	var reply struct {
		ResponseType string `json:"response_type"`
		Text         string `json:"text"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &reply); err != nil || reply.ResponseType != "ephemeral" {
		t.Fatalf("reply %d %s", rr.Code, rr.Body.String())
	}
	secret := regexp.MustCompile(`mmenr_[A-Za-z0-9_-]+`).FindString(reply.Text)
	if secret == "" {
		t.Fatalf("no token in %s", reply.Text)
	}

	rr = post(h, "/register/v1/agents", secret, `{"name":"ops-1","kind":"autonomous","trusted":["kollegin"]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("register: %d %s", rr.Code, rr.Body.String())
	}
	var resp registerResp
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Owner != "dembaca" || mm.assigned["id-agent-ops-1"] != "u-alice" {
		t.Fatalf("owner not bound: %+v %v", resp, mm.assigned)
	}
	if got, want := mm.descs["agent-ops-1"], "for @dembaca · autonomous · trusts @kollegin · via agent-registrar"; got != want {
		t.Fatalf("description:\n got  %q\n want %q", got, want)
	}
	if rr := post(h, "/register/v1/agents", secret, `{"name":"ops-2","responsible":"kollegin","kind":"autonomous"}`); rr.Code != http.StatusForbidden {
		t.Fatalf("responsible mismatch: %d %s", rr.Code, rr.Body.String())
	}

	rr = slash(h, "cmd-token", "u-alice", "revoke all")
	if !strings.Contains(rr.Body.String(), "Revoked 1") {
		t.Fatalf("revoke: %s", rr.Body.String())
	}
	if rr := post(h, "/register/v1/agents", secret, `{"name":"ops-3","kind":"autonomous"}`); rr.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token: %d %s", rr.Code, rr.Body.String())
	}
}

func TestPrivateChannelNeedsMembership(t *testing.T) {
	mm := newFakeMM()
	mm.channelType = "P"
	h := newTestServer(t, mm, true).routes()
	rr := slash(h, "cmd-token", "u-alice", "create --channels secret-room")
	if !strings.Contains(rr.Body.String(), "no access to channel") {
		t.Fatalf("private channel without membership: %s", rr.Body.String())
	}
}

func TestCommandEndpointOnlyWithEnrollment(t *testing.T) {
	h := newTestServer(t, newFakeMM(), false).routes()
	if rr := slash(h, "cmd-token", "u-alice", "create"); rr.Code != http.StatusNotFound && rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("command endpoint without enrollment: %d", rr.Code)
	}
}

func testSeed() []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

func testAttestor(t *testing.T) (*core.Attestor, ed25519.PublicKey) {
	t.Helper()
	a, err := core.NewAttestor(testSeed(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return a, ed25519.NewKeyFromSeed(testSeed()).Public().(ed25519.PublicKey)
}

func TestRegisterAttestsOverHTTP(t *testing.T) {
	a, pub := testAttestor(t)
	mm := newFakeMM()
	h := newAttestingServer(t, mm, true, a).routes()
	rr := slash(h, "cmd-token", "u-alice", "create --kind autonomous")
	var reply struct{ Text string }
	_ = json.Unmarshal(rr.Body.Bytes(), &reply)
	secret := regexp.MustCompile(`mmenr_[A-Za-z0-9_-]+`).FindString(reply.Text)

	check := func(auth, body, via, responsible string, trusted []string) {
		t.Helper()
		rr := post(h, "/register/v1/agents", auth, body)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: %d", body, rr.Code)
		}
		var resp registerResp
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp.Attestation == "" || resp.BotToken == "" || resp.UserID == "" {
			t.Fatalf("response lacks fields: user %q", resp.UserID)
		}
		c, err := core.VerifyAttestation(resp.Attestation, pub, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if c.Via != via || c.Responsible != responsible || strings.Join(c.Trusted, ",") != strings.Join(trusted, ",") ||
			c.TrustedCut != 0 || c.BotID != resp.UserID || c.Username != resp.Username {
			t.Fatalf("claims: %+v", c)
		}
	}
	check(secret, `{"name":"ops-1","kind":"autonomous","trusted":["kollegin","ghost"]}`, "enrollment", "dembaca", []string{"kollegin"})
	check("secret", `{"name":"ops-2","responsible":"kollegin","trusted":["dembaca"]}`, "secret", "kollegin", []string{"dembaca"})
	check("secret", `{"name":"ops-3"}`, "secret", "", []string{})
}

func TestNoKeyNoAttestationAndEmptyKeys(t *testing.T) {
	h := newTestServer(t, newFakeMM(), false).routes()
	rr := post(h, "/register/v1/agents", "secret", `{"name":"plain-1"}`)
	var raw map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &raw)
	if _, ok := raw["attestation"]; ok || rr.Code != http.StatusOK {
		t.Fatalf("attestation present without key: %d %v", rr.Code, raw)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/register/v1/keys", nil))
	if rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != `{"keys":[]}` {
		t.Fatalf("keys: %d %s", rr.Code, rr.Body.String())
	}
}

func TestKeysEndpointShape(t *testing.T) {
	a, pub := testAttestor(t)
	h := newAttestingServer(t, newFakeMM(), false, a).routes()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/register/v1/keys", nil))
	want := `{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"Vkdap1RjR0wChd9d","x":"` +
		base64.RawURLEncoding.EncodeToString(pub) + `"}]}`
	if rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != want ||
		rr.Header().Get("Cache-Control") != "max-age=300" || rr.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("keys: %d %s %v", rr.Code, rr.Body.String(), rr.Header())
	}
}

func TestVersionEndpoint(t *testing.T) {
	h := newAttestingServer(t, newFakeMM(), false, nil).routes()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/register/v1/version", nil))
	want := `{"version":"` + version + `"}`
	if rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != want ||
		rr.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("version: %d %s %v", rr.Code, rr.Body.String(), rr.Header())
	}
}

func TestLoadConfigAttestation(t *testing.T) {
	seed := base64.RawURLEncoding.EncodeToString(testSeed())
	file := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(file, []byte("\n  "+seed+"= \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	load := func(extra map[string]string) (config, error) {
		env := map[string]string{"MATTERMOST_URL": "http://mm", "MATTERMOST_TOKEN": "pat", "REGISTRATION_SECRET": "s"}
		for k, v := range extra {
			env[k] = v
		}
		return loadConfig(func(k string) string { return env[k] })
	}
	if cfg, err := load(nil); err != nil || cfg.attestor != nil {
		t.Fatalf("no key: %v", err)
	}
	cfg, err := load(map[string]string{"ATTESTATION_KEY": seed})
	if err != nil || cfg.attestor == nil || cfg.attestor.Kid() != "Vkdap1RjR0wChd9d" || cfg.attestor.TTL != 30*24*time.Hour {
		t.Fatalf("key: %v", err)
	}
	cfg, err = load(map[string]string{"ATTESTATION_KEY_FILE": file, "ATTESTATION_TTL": "12h"})
	if err != nil || cfg.attestor == nil || cfg.attestor.Kid() != "Vkdap1RjR0wChd9d" || cfg.attestor.TTL != 12*time.Hour {
		t.Fatalf("key file: %v", err)
	}
	for name, extra := range map[string]map[string]string{
		"bad key":      {"ATTESTATION_KEY": "not-a-key"},
		"short key":    {"ATTESTATION_KEY": "AAEC"},
		"both":         {"ATTESTATION_KEY": seed, "ATTESTATION_KEY_FILE": file},
		"bad ttl":      {"ATTESTATION_KEY": seed, "ATTESTATION_TTL": "soon"},
		"missing file": {"ATTESTATION_KEY_FILE": file + ".none"},
	} {
		_, err := load(extra)
		if err == nil || !strings.Contains(err.Error(), "ATTESTATION") {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(err.Error(), seed) || strings.Contains(err.Error(), "not-a-key") {
			t.Fatalf("%s: error echoes the key", name)
		}
	}
}

const (
	modeChan = "c0000000000000000000000000" // public; dembaca (u-alice) is a member
	modeDM   = "d0000000000000000000000000"
)

func newModeServer(t *testing.T, mm *fakeMM, att *core.Attestor, modeTokens []string) *server {
	t.Helper()
	return newModeServerEnroll(t, mm, att, modeTokens, false)
}

func newModeServerEnroll(t *testing.T, mm *fakeMM, att *core.Attestor, modeTokens []string, enroll bool) *server {
	t.Helper()
	mm.chanTypes = map[string]string{modeChan: "O", modeDM: "D"}
	mm.chanMembers = map[string]bool{modeChan + "/u-alice": true, modeDM + "/u-alice": true}
	ts := mm.server(t)
	cfg := config{
		publicChatURL:       "https://chat.example",
		rateLimitPerMin:     100,
		modeRateLimitPerMin: 100,
		modeTokens:          modeTokens,
		modeStore:           filepath.Join(t.TempDir(), "modes.json"),
		attestor:            att,
		mm:                  mattermost.Config{URL: ts.URL, Token: "admin-pat", Team: "ai-agents", TokenDescription: "agent-registrar"},
	}
	cfg.policy.SharedSecret = "secret"
	if enroll {
		cfg.mm.CommandTokens = []string{"cmd-token"}
		cfg.pepper = strings.Repeat("p", 32)
		cfg.enrollStore = filepath.Join(t.TempDir(), "enrollments.json")
	}
	s, err := newServer(cfg, ts.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func modeSlash(h http.Handler, token, userID, channelID, text string) *httptest.ResponseRecorder {
	form := url.Values{"token": {token}, "user_id": {userID}, "channel_id": {channelID}, "team_id": {"team-id"},
		"command": {"/agent-mode"}, "text": {text}}
	req := httptest.NewRequest(http.MethodPost, "/register/v1/mode", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func ephemeral(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var reply struct {
		ResponseType string `json:"response_type"`
		Text         string `json:"text"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &reply); err != nil || reply.ResponseType != "ephemeral" {
		t.Fatalf("not an ephemeral reply: %d %s", rr.Code, rr.Body.String())
	}
	return reply.Text
}

func getMode(h http.Handler, id string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/register/v1/modes/"+id, nil))
	return rr
}

func TestModeCommandAndRecordOverHTTP(t *testing.T) {
	a, pub := testAttestor(t)
	mm := newFakeMM()
	// Modes work without enrollment tokens (no SLASH_COMMAND_TOKEN, no pepper).
	h := newModeServer(t, mm, a, []string{"mode-a", "mode-b"}).routes()

	for _, tok := range []string{"wrong", ""} {
		if rr := modeSlash(h, tok, "u-alice", modeChan, "coordinator"); rr.Code != http.StatusUnauthorized {
			t.Fatalf("token %q: %d %s", tok, rr.Code, rr.Body.String())
		}
	}
	if txt := ephemeral(t, modeSlash(h, "mode-a", "b2", modeChan, "coordinator")); !strings.Contains(txt, "no bots") {
		t.Fatalf("bot: %s", txt)
	}
	if rr := getMode(h, modeChan); rr.Code != http.StatusNotFound || strings.TrimSpace(rr.Body.String()) != `{"error":"no mode set"}` {
		t.Fatalf("unset: %d %s", rr.Code, rr.Body.String())
	}
	if txt := ephemeral(t, modeSlash(h, "mode-a", "u-alice", modeChan, "")); !strings.Contains(txt, "not set") {
		t.Fatalf("status: %s", txt)
	}
	if txt := ephemeral(t, modeSlash(h, "mode-b", "u-alice", modeDM, "coordinator")); !strings.Contains(txt, "direct or group") {
		t.Fatalf("dm: %s", txt)
	}
	if txt := ephemeral(t, modeSlash(h, "mode-a", "u2", modeChan, "coordinator")); !strings.Contains(txt, "Only members") {
		t.Fatalf("non-member: %s", txt)
	}
	if txt := ephemeral(t, modeSlash(h, "mode-a", "u-alice", modeChan, "delegated")); !strings.Contains(txt, "ADR-005 phase 3") {
		t.Fatalf("delegated: %s", txt)
	}
	if txt := ephemeral(t, modeSlash(h, "mode-a", "u-alice", modeChan, "please")); !strings.Contains(txt, "/agent-mode coordinator") {
		t.Fatalf("help: %s", txt)
	}
	if rr := getMode(h, modeChan); rr.Code != http.StatusNotFound {
		t.Fatalf("refused calls stored a mode: %d", rr.Code)
	}

	before := time.Now()
	if txt := ephemeral(t, modeSlash(h, "mode-b", "u-alice", modeChan, "coordinator")); !strings.Contains(txt, "now `coordinator`") {
		t.Fatalf("set: %s", txt)
	}
	rr := getMode(h, modeChan)
	var body struct {
		Record string `json:"record"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || rr.Code != http.StatusOK || body.Record == "" ||
		rr.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("get: %d", rr.Code)
	}
	c, err := core.VerifyMode(body.Record, pub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if c.ChannelID != modeChan || c.Mode != "coordinator" || c.SetBy != "dembaca" || c.SetByID != "u-alice" ||
		c.SetAtMs < before.UnixMilli() || c.SetAtMs > time.Now().UnixMilli() || c.Exp-c.Iat != 3600 {
		t.Fatalf("claims: %+v", c)
	}
	if _, err := core.VerifyAttestation(body.Record, pub, time.Now()); err == nil {
		t.Fatal("mode record verifies as an attestation")
	}
	if txt := ephemeral(t, modeSlash(h, "mode-a", "u-alice", modeChan, "status")); !strings.Contains(txt, "`coordinator`, set by @dembaca") {
		t.Fatalf("status after set: %s", txt)
	}

	for _, id := range []string{"short", "C0000000000000000000000000", "c00000000000000000000000000", "c000000000000000000000000_"} {
		if rr := getMode(h, id); rr.Code != http.StatusBadRequest {
			t.Fatalf("%q: %d", id, rr.Code)
		}
	}
}

func TestModeRecordHasItsOwnRateBucket(t *testing.T) {
	a, _ := testAttestor(t)
	s := newModeServer(t, newFakeMM(), a, nil)
	s.rate, s.modeRate = newLimiter(2), newLimiter(3)
	h := s.routes()
	for i := 0; i < 3; i++ {
		if rr := getMode(h, modeChan); rr.Code != http.StatusNotFound {
			t.Fatalf("mode get %d: %d", i, rr.Code)
		}
	}
	if rr := getMode(h, modeChan); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("mode bucket not enforced: %d", rr.Code)
	}
	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/register/v1/keys", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("keys %d after the mode bucket ran out: %d", i, rr.Code)
		}
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/register/v1/keys", nil))
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("main bucket not enforced: %d", rr.Code)
	}
}

func TestModeRoutesFollowConfig(t *testing.T) {
	a, _ := testAttestor(t)
	gone := func(rr *httptest.ResponseRecorder) bool {
		return rr.Code == http.StatusNotFound || rr.Code == http.StatusMethodNotAllowed
	}
	// No attestation key: neither route.
	h := newModeServer(t, newFakeMM(), nil, nil).routes()
	if rr := getMode(h, modeChan); rr.Code != http.StatusNotFound || strings.Contains(rr.Body.String(), "no mode set") {
		t.Fatalf("GET without key: %d %s", rr.Code, rr.Body.String())
	}
	if !gone(modeSlash(h, "mode-a", "u-alice", modeChan, "status")) {
		t.Fatal("command without key")
	}
	// Each command takes only its own verification tokens.
	h = newModeServerEnroll(t, newFakeMM(), a, []string{"mode-a"}, true).routes()
	if rr := modeSlash(h, "cmd-token", "u-alice", modeChan, "status"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("token command's token on the mode command: %d", rr.Code)
	}
	if rr := slash(h, "mode-a", "u-alice", "list"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("mode command's token on the token command: %d", rr.Code)
	}
	if txt := ephemeral(t, modeSlash(h, "mode-a", "u-alice", modeChan, "status")); !strings.Contains(txt, "not set") {
		t.Fatalf("mode command next to enrollment: %s", txt)
	}
	// Key without MODE_COMMAND_TOKEN: the GET only.
	h = newModeServer(t, newFakeMM(), a, nil).routes()
	if rr := getMode(h, modeChan); rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "no mode set") {
		t.Fatalf("GET with key: %d %s", rr.Code, rr.Body.String())
	}
	if !gone(modeSlash(h, "mode-a", "u-alice", modeChan, "status")) {
		t.Fatal("command without MODE_COMMAND_TOKEN")
	}
}

func TestLoadConfigModeCommand(t *testing.T) {
	seed := base64.RawURLEncoding.EncodeToString(testSeed())
	load := func(extra map[string]string) (config, error) {
		env := map[string]string{"MATTERMOST_URL": "http://mm", "MATTERMOST_TOKEN": "pat", "REGISTRATION_SECRET": "s"}
		for k, v := range extra {
			env[k] = v
		}
		return loadConfig(func(k string) string { return env[k] })
	}
	_, err := load(map[string]string{"MODE_COMMAND_TOKEN": "m"})
	if err == nil || !strings.Contains(err.Error(), "MODE_COMMAND_TOKEN needs ATTESTATION_KEY") {
		t.Fatalf("mode without key: %v", err)
	}
	cfg, err := load(map[string]string{"MODE_COMMAND_TOKEN": "m1, m2", "ATTESTATION_KEY": seed})
	if err != nil || strings.Join(cfg.modeTokens, "|") != "m1|m2" || cfg.modeStore != "/data/modes.json" ||
		cfg.modeRateLimitPerMin != 120 || len(cfg.mm.CommandTokens) != 0 {
		t.Fatalf("mode with key: %+v %v", cfg.modeTokens, err)
	}
	cfg, err = load(map[string]string{"MODE_COMMAND_TOKEN": "m", "ATTESTATION_KEY": seed, "MODE_STORE": "/x/m.json"})
	if err != nil || cfg.modeStore != "/x/m.json" {
		t.Fatalf("mode store: %v", err)
	}
	if cfg, err := load(nil); err != nil || len(cfg.modeTokens) != 0 {
		t.Fatalf("no mode command: %v", err)
	}
}

func TestClientIPCountsTrustedHopsFromTheRight(t *testing.T) {
	cases := []struct {
		name string
		hops int
		xff  []string
		want string
	}{
		{"forged first entry, one hop", 1, []string{"6.6.6.6, 203.0.113.9"}, "203.0.113.9"},
		{"one hop, single entry", 1, []string{"203.0.113.9"}, "203.0.113.9"},
		{"two hops", 2, []string{"6.6.6.6, 203.0.113.9, 10.0.0.2"}, "203.0.113.9"},
		{"too few entries", 2, []string{"203.0.113.9"}, "192.0.2.1"},
		{"no header", 1, nil, "192.0.2.1"},
		{"zero hops ignores the header", 0, []string{"203.0.113.9"}, "192.0.2.1"},
		{"repeated header lines are joined", 1, []string{"6.6.6.6", "203.0.113.9"}, "203.0.113.9"},
	}
	for _, c := range cases {
		s := &server{cfg: config{trustedProxyHops: c.hops}}
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "192.0.2.1:4711"
		for _, h := range c.xff {
			r.Header.Add("X-Forwarded-For", h)
		}
		if got := s.clientIP(r); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	s := &server{}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[2001:db8::1]:4711"
	if got := s.clientIP(r); got != "2001:db8::1" {
		t.Errorf("ipv6 peer: got %q", got)
	}
}

func TestLoadConfigTrustedProxyHops(t *testing.T) {
	load := func(v string) (config, error) {
		env := map[string]string{"MATTERMOST_URL": "http://mm", "MATTERMOST_TOKEN": "pat", "REGISTRATION_SECRET": "s", "TRUSTED_PROXY_HOPS": v}
		return loadConfig(func(k string) string { return env[k] })
	}
	for v, want := range map[string]int{"": 1, "0": 0, "2": 2} {
		if cfg, err := load(v); err != nil || cfg.trustedProxyHops != want {
			t.Errorf("%q: got %d, %v", v, cfg.trustedProxyHops, err)
		}
	}
	if _, err := load("x"); err == nil {
		t.Error("not a number must fail")
	}
}
