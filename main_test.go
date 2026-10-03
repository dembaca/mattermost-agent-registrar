package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEnvBool(t *testing.T) {
	t.Setenv("TEST_BOOL", "")
	if got := envBool("TEST_BOOL", true); !got {
		t.Fatalf("empty env: want default true")
	}
	for _, v := range []string{"true", "TRUE", "1", "yes", "on"} {
		t.Setenv("TEST_BOOL", v)
		if !envBool("TEST_BOOL", false) {
			t.Fatalf("%q: want true", v)
		}
	}
	for _, v := range []string{"false", "FALSE", "0", "no", "off"} {
		t.Setenv("TEST_BOOL", v)
		if envBool("TEST_BOOL", true) {
			t.Fatalf("%q: want false", v)
		}
	}
	t.Setenv("TEST_BOOL", "maybe")
	if !envBool("TEST_BOOL", true) {
		t.Fatalf("unknown value: want default true")
	}
	_ = os.Unsetenv("TEST_BOOL")
}

func TestHideBotDirectChannelIgnoresPreferenceFailure(t *testing.T) {
	var prefsCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v4/users/me", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(mmUser{ID: "admin-id", Username: "admin"})
	})
	mux.HandleFunc("PUT /api/v4/users/me/preferences", func(w http.ResponseWriter, r *http.Request) {
		prefsCalls.Add(1)
		body, _ := io.ReadAll(r.Body)
		var prefs []mmPreference
		if err := json.Unmarshal(body, &prefs); err != nil {
			t.Errorf("prefs json: %v", err)
		}
		if len(prefs) != 1 || prefs[0].UserID != "admin-id" || prefs[0].Category != "direct_channel_show" ||
			prefs[0].Name != "bot-id" || prefs[0].Value != "false" {
			t.Errorf("unexpected prefs: %s", body)
		}
		// Simulate Mattermost rejecting a bad preference (e.g. bogus name/user).
		http.Error(w, `{"message":"invalid preference"}`, http.StatusBadRequest)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	s := &server{
		cfg:    config{mmURL: ts.URL, mmToken: "tok", hideBotDM: true},
		client: ts.Client(),
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	// Must not panic / must return; registration caller ignores the outcome.
	s.hideBotDirectChannel(context.Background(), "bot-id")
	if prefsCalls.Load() != 1 {
		t.Fatalf("prefs calls: got %d want 1", prefsCalls.Load())
	}
}

func TestRegisterSucceedsWhenHideDMFails(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v4/users/username/", func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	})
	mux.HandleFunc("POST /api/v4/bots", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(mmBot{UserID: "bot-id", Username: "agent-cursor-1", DisplayName: "Cursor 1"})
	})
	mux.HandleFunc("GET /api/v4/users/me", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(mmUser{ID: "admin-id"})
	})
	mux.HandleFunc("PUT /api/v4/users/me/preferences", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusBadRequest)
	})
	mux.HandleFunc("POST /api/v4/users/bot-id/tokens", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(mmToken{Token: "bot-token", ID: "tok-id"})
	})
	mux.HandleFunc("GET /api/v4/teams/name/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "skip", http.StatusNotFound)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	s := &server{
		cfg: config{
			mmURL:           ts.URL,
			publicChatURL:   "https://chat.example",
			mmToken:         "admin-pat",
			regSecret:       "secret",
			botPrefix:       "agent-",
			defaultTeam:     "ai-agents",
			defaultChannel:  "agents",
			hideBotDM:       true,
			rateLimitPerMin: 100,
		},
		client: ts.Client(),
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		hits:   map[string][]time.Time{},
	}

	body := `{"name":"cursor-1","display_name":"Cursor 1"}`
	req := httptest.NewRequest(http.MethodPost, "/register/v1/agents", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.handleRegister(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d body %s", rr.Code, rr.Body.String())
	}
	var resp registerResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.BotToken != "bot-token" || resp.UserID != "bot-id" {
		t.Fatalf("unexpected resp: %+v", resp)
	}
}
