package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

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
}

// fakeMM is a minimal Mattermost API for the HTTP-level tests.
type fakeMM struct {
	mu          sync.Mutex
	users       map[string]mattermost.User // by username
	descs       map[string]string          // bot username -> description
	assigned    map[string]string          // bot id -> owner id
	prefsFail   bool
	channelType string
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
	mux.HandleFunc("GET /api/v4/channels/{ch}/members/{uid}", func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil) // nobody is a channel member; public channels still pass
	})
	mux.HandleFunc("POST /api/v4/channels/{ch}/members", func(http.ResponseWriter, *http.Request) {})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func newTestServer(t *testing.T, mm *fakeMM, enroll bool) *server {
	t.Helper()
	ts := mm.server(t)
	cfg := config{
		publicChatURL:   "https://chat.example",
		rateLimitPerMin: 100,
		mm: mattermost.Config{URL: ts.URL, Token: "admin-pat", Team: "ai-agents", HideBotDM: true,
			TokenDescription: "agent-registrar"},
	}
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
