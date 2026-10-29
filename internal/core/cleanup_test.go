package core

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func revokeCmd(s *Service, which string) string {
	inv := alice
	inv.Text = "revoke " + which
	return s.Command(context.Background(), inv)
}

func mustRegister(t *testing.T, s *Service, cred, name string) {
	t.Helper()
	if _, err := register(s, cred, "name="+name); err != nil {
		t.Fatalf("register %s: %v", name, err)
	}
}

func TestRevokeUnregistersTheTokensBots(t *testing.T) {
	f := newFake()
	s, _ := newService(t, f, "")
	sec1, id1 := mint(t, s, alice, "--max-bots 3")
	sec2, id2 := mint(t, s, alice, "")
	mustRegister(t, s, sec1, "one-a")
	mustRegister(t, s, sec1, "one-b")
	mustRegister(t, s, sec2, "two-a")
	mustRegister(t, s, "shared", "unbound")

	out := revokeCmd(s, id1)
	if !strings.Contains(out, "Revoked 1 token(s); unregistered 2 bot(s)") {
		t.Fatalf("revoke: %s", out)
	}
	for _, id := range []string{"bot-bot-x-one-a", "bot-bot-x-one-b"} {
		if !f.revoked[id] {
			t.Fatalf("%s not unregistered", id)
		}
	}
	if f.revoked["bot-bot-x-two-a"] || f.revoked["bot-bot-x-unbound"] {
		t.Fatalf("other bots unregistered: %v", f.revoked)
	}
	if n := len(s.Store.AgentsOf(id1)); n != 0 {
		t.Fatalf("records of revoked token left: %d", n)
	}
	// Revoking it again finds nothing left to do.
	if out := revokeCmd(s, id1); !strings.Contains(out, "No active token") {
		t.Fatalf("second revoke: %s", out)
	}
	if out := revokeCmd(s, "all"); !strings.Contains(out, "Revoked 1 token(s); unregistered 1 bot(s)") || !f.revoked["bot-bot-x-two-a"] {
		t.Fatalf("revoke all: %s", out)
	}
	_ = id2
}

func TestRevokeReportsFailuresAndRetries(t *testing.T) {
	f := newFake()
	s, c := newService(t, f, "")
	sec, id := mint(t, s, alice, "")
	mustRegister(t, s, sec, "ok-bot")
	mustRegister(t, s, sec, "stuck-bot")
	f.failRevoke = map[string]bool{"bot-x-stuck-bot": true}

	out := revokeCmd(s, id)
	if !strings.Contains(out, "unregistered 1 bot(s)") || !strings.Contains(out, "failed (@bot-x-stuck-bot)") ||
		!strings.Contains(out, "/agent-token revoke "+id) {
		t.Fatalf("revoke with failure: %s", out)
	}
	if recs := s.Store.AgentsOf(id); len(recs) != 1 || recs[0].Username != "bot-x-stuck-bot" {
		t.Fatalf("failed bot must stay recorded: %+v", recs)
	}
	// The token keeps its live bot, so pruning keeps the token.
	c.t = c.t.Add(365 * 24 * time.Hour)
	if n, err := s.Store.Prune(c.t, 0); err != nil || n != 0 {
		t.Fatalf("pruned a token with a live bot: %d %v", n, err)
	}

	f.failRevoke = nil
	if out := revokeCmd(s, id); !strings.Contains(out, "Revoked 0 token(s); unregistered 1 bot(s)") {
		t.Fatalf("retry: %s", out)
	}
	if n, err := s.Store.Prune(c.t, 0); err != nil || n != 1 {
		t.Fatalf("prune after cleanup: %d %v", n, err)
	}
}

func TestRevokeOnlyForgetsAReusedUsername(t *testing.T) {
	f := newFake()
	s, _ := newService(t, f, "")
	sec, id := mint(t, s, alice, "")
	mustRegister(t, s, sec, "reused")
	gone := mustAgent(t, f, "bot-x-reused")
	// Deleted behind the registrar's back and recreated by someone else.
	f.agents["bot-x-reused"] = Agent{ID: "someone-else", Username: "bot-x-reused"}

	out := revokeCmd(s, id)
	if !strings.Contains(out, "unregistered 0 bot(s)") || f.revoked["someone-else"] || f.revoked[gone.ID] {
		t.Fatalf("revoke touched another account: %s %v", out, f.revoked)
	}
	if n := len(s.Store.AgentsOf(id)); n != 0 {
		t.Fatalf("stale record kept: %d", n)
	}
}

func mustAgent(t *testing.T, f *fakeProvider, username string) Agent {
	t.Helper()
	a, ok := f.agents[username]
	if !ok {
		t.Fatalf("no agent %s", username)
	}
	return a
}

func TestPruneDropsOnlyStaleTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollments.json")
	f := newFake()
	s, c := newService(t, f, path)
	s.Policy.MaxTokensPerUser = 5
	start := c.t
	_, active := mint(t, s, alice, "--expires 90d")
	_, expired := mint(t, s, alice, "--expires 1d")
	_, revoked := mint(t, s, alice, "--expires 90d")
	secLive, expiredLive := mint(t, s, alice, "--expires 2d")
	mustRegister(t, s, secLive, "still-here")
	c.t = start.Add(12 * time.Hour)
	if _, err := s.Store.Revoke("u-alice", revoked, c.t); err != nil {
		t.Fatal(err)
	}
	retention := 7 * 24 * time.Hour
	ids := func() string {
		var out []string
		for _, tok := range s.Store.Owned("u-alice") {
			out = append(out, tok.ID)
		}
		return strings.Join(out, ",")
	}
	all := strings.Join([]string{active, expired, revoked, expiredLive}, ",")

	// Within the retention window nothing goes.
	c.t = start.Add(12*time.Hour + retention - time.Minute)
	if n, err := s.Store.Prune(c.t, retention); err != nil || n != 0 || ids() != all {
		t.Fatalf("pruned early: %d %v %s", n, err, ids())
	}
	// Revoked 12h in: its window ends before the expired one's.
	c.t = start.Add(12*time.Hour + retention)
	if n, _ := s.Store.Prune(c.t, retention); n != 1 || strings.Contains(ids(), revoked) {
		t.Fatalf("revoked token not pruned: %s", ids())
	}
	c.t = start.Add(100 * 24 * time.Hour)
	s.Policy.TokenRetention = retention
	s.PruneTokens()
	if got := ids(); got != expiredLive {
		t.Fatalf("after expiry of all: %s, want only the token with a live bot %s", got, expiredLive)
	}

	// Pruning is written to the store.
	st, err := OpenStore(path, []byte("pepper-pepper-pepper-pepper-pepper"))
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Owned("u-alice"); len(got) != 1 || got[0].ID != expiredLive {
		t.Fatalf("reloaded store: %+v", got)
	}
}
