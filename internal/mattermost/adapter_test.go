package mattermost

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/dembaca/mattermost-agent-registrar/internal/core"
)

func adapter(t *testing.T, mux *http.ServeMux) *Adapter {
	t.Helper()
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return &Adapter{
		Cfg:    Config{URL: ts.URL, Token: "tok", Team: "team-a", HideBotDM: true},
		Client: ts.Client(),
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestHideBotDirectChannelIgnoresPreferenceFailure(t *testing.T) {
	var prefsCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v4/users/me", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(User{ID: "admin-id", Username: "admin"})
	})
	mux.HandleFunc("PUT /api/v4/users/me/preferences", func(w http.ResponseWriter, r *http.Request) {
		prefsCalls.Add(1)
		body, _ := io.ReadAll(r.Body)
		var prefs []Preference
		if err := json.Unmarshal(body, &prefs); err != nil {
			t.Errorf("prefs json: %v", err)
		}
		if len(prefs) != 1 || prefs[0].UserID != "admin-id" || prefs[0].Category != "direct_channel_show" ||
			prefs[0].Name != "bot-id" || prefs[0].Value != "false" {
			t.Errorf("unexpected prefs: %s", body)
		}
		http.Error(w, `{"message":"invalid preference"}`, http.StatusBadRequest)
	})
	m := adapter(t, mux)
	m.HideBotDirectChannel(context.Background(), "bot-id")
	if prefsCalls.Load() != 1 {
		t.Fatalf("prefs calls: got %d want 1", prefsCalls.Load())
	}
}

// dmMux serves the routes HideBotDirectChannel uses and records the calls in order.
func dmMux(t *testing.T, calls *[]string, directFails bool) *http.ServeMux {
	t.Helper()
	var mu sync.Mutex
	rec := func(s string) {
		mu.Lock()
		defer mu.Unlock()
		*calls = append(*calls, s)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v4/users/me", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(User{ID: "admin-id", Username: "admin"})
	})
	mux.HandleFunc("PUT /api/v4/users/me/preferences", func(w http.ResponseWriter, _ *http.Request) {
		rec("prefs")
	})
	mux.HandleFunc("POST /api/v4/channels/direct", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec("direct " + string(body))
		if directFails {
			http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"id":"dm-id","type":"D"}`))
	})
	mux.HandleFunc("POST /api/v4/channels/members/me/view", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec("view " + string(body))
		_, _ = w.Write([]byte(`{"status":"OK"}`))
	})
	mux.HandleFunc("POST /api/v4/bots/{id}/disable", func(w http.ResponseWriter, _ *http.Request) {
		rec("disable")
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("GET /api/v4/users/{id}/tokens", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	return mux
}

func TestHideBotDirectChannelMarksDMRead(t *testing.T) {
	var calls []string
	m := adapter(t, dmMux(t, &calls, false))
	m.HideBotDirectChannel(context.Background(), "bot-id")
	want := []string{"prefs", `direct ["admin-id","bot-id"]`, `view {"channel_id":"dm-id"}`}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls: got %q want %q", calls, want)
	}
}

func TestHideBotDirectChannelDirectFailure(t *testing.T) {
	var calls []string
	m := adapter(t, dmMux(t, &calls, true))
	m.HideBotDirectChannel(context.Background(), "bot-id")
	want := []string{"prefs", `direct ["admin-id","bot-id"]`}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls: got %q want %q", calls, want)
	}
}

func TestRevokeAgentMarksDMRead(t *testing.T) {
	for _, hide := range []bool{true, false} {
		var calls []string
		m := adapter(t, dmMux(t, &calls, false))
		m.Cfg.HideBotDM = hide
		if err := m.RevokeAgent(context.Background(), core.Agent{ID: "bot-id"}); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		want := []string{"disable"}
		if hide {
			want = []string{"prefs", `direct ["admin-id","bot-id"]`, `view {"channel_id":"dm-id"}`, "disable"}
		}
		if !reflect.DeepEqual(calls, want) {
			t.Errorf("HideBotDM=%v: calls %q want %q", hide, calls, want)
		}
	}
}

func TestHumanCanAccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v4/teams/name/team-a", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"t1"}`))
	})
	chans := map[string]string{"pub": "O", "priv": "P"}
	mux.HandleFunc("GET /api/v4/teams/t1/channels/name/{ch}", func(w http.ResponseWriter, r *http.Request) {
		typ, ok := chans[r.PathValue("ch")]
		if !ok {
			http.NotFound(w, nil)
			return
		}
		_, _ = w.Write([]byte(`{"id":"c-` + r.PathValue("ch") + `","type":"` + typ + `"}`))
	})
	team := map[string]string{"in": `{"delete_at":0}`, "member": `{"delete_at":0}`, "left": `{"delete_at":5}`}
	mux.HandleFunc("GET /api/v4/teams/t1/members/{uid}", func(w http.ResponseWriter, r *http.Request) {
		b, ok := team[r.PathValue("uid")]
		if !ok {
			http.NotFound(w, nil)
			return
		}
		_, _ = w.Write([]byte(b))
	})
	mux.HandleFunc("GET /api/v4/channels/{cid}/members/{uid}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("uid") == "member" {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		http.NotFound(w, nil)
	})
	m := adapter(t, mux)
	for _, c := range []struct {
		user, ch string
		want     bool
	}{
		{"in", "pub", true},      // team member, public channel
		{"in", "priv", false},    // team member, private channel without membership
		{"member", "priv", true}, // channel member
		{"left", "pub", false},   // left the team
		{"out", "pub", false},    // never in the team
	} {
		got, err := m.HumanCanAccess(context.Background(), core.Human{ID: c.user}, c.ch)
		if err != nil || got != c.want {
			t.Errorf("%s in %s: got %v %v, want %v", c.user, c.ch, got, err, c.want)
		}
	}
	if _, err := m.HumanCanAccess(context.Background(), core.Human{ID: "in"}, "nope"); !errors.Is(err, core.ErrNoSuchChannel) {
		t.Errorf("missing channel: %v", err)
	}
}

func TestVerifyInvocationRefusesGuests(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v4/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(User{ID: r.PathValue("id"), Username: "g", Roles: "system_guest"})
	})
	m := adapter(t, mux)
	m.Cfg.CommandTokens = []string{"cmd"}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.PostForm = map[string][]string{"token": {"cmd"}, "user_id": {"g1"}}
	if _, err := m.VerifyInvocation(req); !errors.Is(err, core.ErrForbidden) {
		t.Fatalf("guest: %v", err)
	}
}

func TestHumanInChannel(t *testing.T) {
	mux := http.NewServeMux()
	types := map[string]string{"pub": "O", "priv": "P", "dm": "D", "grp": "G"}
	mux.HandleFunc("GET /api/v4/channels/{cid}", func(w http.ResponseWriter, r *http.Request) {
		typ, ok := types[r.PathValue("cid")]
		if !ok {
			http.NotFound(w, nil)
			return
		}
		_, _ = w.Write([]byte(`{"id":"` + r.PathValue("cid") + `","type":"` + typ + `"}`))
	})
	mux.HandleFunc("GET /api/v4/channels/{cid}/members/{uid}", func(w http.ResponseWriter, r *http.Request) {
		switch r.PathValue("uid") {
		case "member":
			_, _ = w.Write([]byte(`{}`))
		case "broken":
			http.Error(w, "boom", http.StatusInternalServerError)
		default:
			http.NotFound(w, nil)
		}
	})
	m := adapter(t, mux)
	ctx := context.Background()
	for _, c := range []struct {
		user, ch string
		want     bool
	}{
		{"member", "pub", true},
		{"member", "priv", true},
		{"other", "pub", false}, // public, but not a member
		{"other", "priv", false},
	} {
		got, err := m.HumanInChannel(ctx, core.Human{ID: c.user}, c.ch)
		if err != nil || got != c.want {
			t.Errorf("%s in %s: got %v %v, want %v", c.user, c.ch, got, err, c.want)
		}
	}
	for _, ch := range []string{"dm", "grp"} {
		if _, err := m.HumanInChannel(ctx, core.Human{ID: "member"}, ch); !errors.Is(err, core.ErrNotTeamChannel) {
			t.Errorf("%s: %v", ch, err)
		}
	}
	if _, err := m.HumanInChannel(ctx, core.Human{ID: "member"}, "nope"); !errors.Is(err, core.ErrNoSuchChannel) {
		t.Errorf("missing channel: %v", err)
	}
	if _, err := m.HumanInChannel(ctx, core.Human{ID: "broken"}, "pub"); err == nil || errors.Is(err, core.ErrNoSuchChannel) {
		t.Errorf("upstream error: %v", err)
	}
}

func TestVerifyInvocationCarriesChannel(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v4/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(User{ID: r.PathValue("id"), Username: "Alice"})
	})
	m := adapter(t, mux)
	m.Cfg.CommandTokens = []string{"mode-cmd"}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.PostForm = map[string][]string{"token": {"mode-cmd"}, "user_id": {"u1"}, "channel_id": {"c1"},
		"command": {"/agent-mode"}, "text": {"status"}}
	inv, err := m.VerifyInvocation(req)
	if err != nil || inv.ChannelID != "c1" || inv.Human.Handle != "alice" || inv.Command != "/agent-mode" || inv.Text != "status" {
		t.Fatalf("%+v %v", inv, err)
	}
}
