package core

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var (
	secretRE = regexp.MustCompile(`mmenr_[A-Za-z0-9_-]+`)
	idRE     = regexp.MustCompile("token `([0-9a-f]{8})` created")
)

var alice = Invocation{Human: Human{ID: "u-alice", Handle: "alice"}, Command: "/agent-token"}

// mint runs "/agent-token create <args>" as who and returns secret and id.
func mint(t *testing.T, s *Service, who Invocation, args string) (string, string) {
	t.Helper()
	who.Text = "create " + args
	out := s.Command(context.Background(), who)
	sec, id := secretRE.FindString(out), idRE.FindStringSubmatch(out)
	if sec == "" || id == nil {
		t.Fatalf("create %q: no token in reply:\n%s", args, out)
	}
	return sec, id[1]
}

func register(s *Service, cred, body string) (Registration, error) {
	req := RegisterRequest{}
	for _, kv := range strings.Split(body, ";") {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "name":
			req.Name = v
		case "responsible":
			req.Responsible = v
		case "kind":
			req.Kind = v
		case "trusted":
			req.Trusted = strings.Split(v, ",")
		case "channels":
			req.Channels = strings.Split(v, ",")
		}
	}
	return s.Register(context.Background(), cred, req)
}

func TestTokenCreateListRevoke(t *testing.T) {
	f := newFake()
	s, _ := newService(t, f, "")
	ctx := context.Background()

	sec, id := mint(t, s, alice, `--expires 7d --max-bots 3 --channels proj,agents --kind autonomous --label "my laptop"`)
	if !strings.HasPrefix(sec, TokenPrefix) || len(sec) < len(TokenPrefix)+40 {
		t.Fatalf("token too short: %q", sec)
	}
	tok, ok := s.Store.Lookup(sec)
	if !ok || tok.ID != id || tok.OwnerID != "u-alice" || tok.Kind != "autonomous" || tok.MaxBots != 3 ||
		tok.Label != "my laptop" || strings.Join(tok.Channels, ",") != "proj,agents" ||
		!tok.ExpiresAt.Equal(s.now().Add(7*24*time.Hour)) {
		t.Fatalf("stored token: %+v", tok)
	}

	list := alice
	list.Text = "list"
	out := s.Command(ctx, list)
	if !strings.Contains(out, id) || !strings.Contains(out, "my laptop") || strings.Contains(out, sec) {
		t.Fatalf("list:\n%s", out)
	}
	bob := Invocation{Human: Human{ID: "u-bob", Handle: "bob"}, Text: "list"}
	if out := s.Command(ctx, bob); strings.Contains(out, id) {
		t.Fatalf("bob sees alice's token:\n%s", out)
	}
	bob.Text = "revoke " + id
	if out := s.Command(ctx, bob); !strings.Contains(out, "No active token") {
		t.Fatalf("bob revoked alice's token: %s", out)
	}

	rev := alice
	rev.Text = "revoke " + id
	if out := s.Command(ctx, rev); !strings.Contains(out, "Revoked 1") {
		t.Fatalf("revoke: %s", out)
	}
	if out := s.Command(ctx, list); !strings.Contains(out, "no active enrollment tokens") || !strings.Contains(out, "1 expired or revoked") {
		t.Fatalf("list after revoke:\n%s", out)
	}

	mint(t, s, alice, "")
	mint(t, s, alice, "")
	rev.Text = "revoke all"
	if out := s.Command(ctx, rev); !strings.Contains(out, "Revoked 2") {
		t.Fatalf("revoke all: %s", out)
	}
}

func TestTokenCreateRefusesBadScope(t *testing.T) {
	f := newFake()
	s, _ := newService(t, f, "")
	ctx := context.Background()
	for args, want := range map[string]string{
		"--expires 91d":     "at most 90d",
		"--max-bots 6":      "from 1 to 5",
		"--kind admin":      "session or autonomous",
		"--channels secret": "does not exist",
		"--channels proj":   "", // alice is a member
		"--bogus 1":         "Unknown option",
	} {
		inv := alice
		inv.Text = "create " + args
		out := s.Command(ctx, inv)
		if want == "" {
			if secretRE.FindString(out) == "" {
				t.Fatalf("%s: want a token, got %s", args, out)
			}
			continue
		}
		if !strings.Contains(out, want) || secretRE.FindString(out) != "" {
			t.Fatalf("%s: want %q, got %s", args, want, out)
		}
	}
	// bob is in the team but not in the private channel proj.
	bob := Invocation{Human: Human{ID: "u-bob", Handle: "bob"}, Text: "create --channels proj"}
	if out := s.Command(ctx, bob); !strings.Contains(out, "no access to channel `proj`") {
		t.Fatalf("bob: %s", out)
	}
	// carol is not in the team at all: not even the public default channel.
	carol := Invocation{Human: Human{ID: "u-carol", Handle: "carol"}, Text: "create"}
	if out := s.Command(ctx, carol); !strings.Contains(out, "no access to channel `agents`") {
		t.Fatalf("carol: %s", out)
	}
	// Per-user cap: alice holds one token already, cap is 3.
	mint(t, s, alice, "")
	mint(t, s, alice, "")
	inv := alice
	inv.Text = "create"
	if out := s.Command(ctx, inv); !strings.Contains(out, "Revoke one first") {
		t.Fatalf("cap: %s", out)
	}
}

func TestStoreKeepsOnlyTheHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollments.json")
	f := newFake()
	s, _ := newService(t, f, path)
	sec, id := mint(t, s, alice, "--label ci")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.TrimPrefix(sec, TokenPrefix)
	if strings.Contains(string(data), raw) || !strings.Contains(string(data), id) {
		t.Fatalf("store holds the secret or lacks the id:\n%s", data)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("store mode %v", fi.Mode().Perm())
	}
	// Reopened, the token still resolves; with another pepper it does not.
	st, err := OpenStore(path, []byte("pepper-pepper-pepper-pepper-pepper"))
	if err != nil {
		t.Fatal(err)
	}
	if tok, ok := st.Lookup(sec); !ok || tok.ID != id {
		t.Fatalf("reopened lookup: %+v %v", tok, ok)
	}
	other, _ := OpenStore(path, []byte("another-pepper-another-pepper-xx"))
	if _, ok := other.Lookup(sec); ok {
		t.Fatal("lookup must depend on the pepper")
	}
}

func TestExpiredAndRevokedTokensAreRefused(t *testing.T) {
	f := newFake()
	s, c := newService(t, f, "")
	sec, id := mint(t, s, alice, "--expires 1h")
	c.t = c.t.Add(2 * time.Hour)
	if _, err := register(s, sec, "name=late-1"); !errors.Is(err, ErrUnauthorized) || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired: %v", err)
	}
	sec2, id2 := mint(t, s, alice, "")
	if _, err := s.Store.Revoke("u-alice", id2, c.t); err != nil {
		t.Fatal(err)
	}
	if _, err := register(s, sec2, "name=late-2"); !errors.Is(err, ErrUnauthorized) || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked: %v", err)
	}
	if _, err := register(s, TokenPrefix+"forged", "name=late-3"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unknown: %v", err)
	}
	if len(f.agents) != 0 {
		t.Fatalf("agents created: %v (%s)", f.agents, id)
	}
}

func TestEnrollmentBindsTheOwner(t *testing.T) {
	f := newFake()
	s, _ := newService(t, f, "")
	sec, id := mint(t, s, alice, "--kind autonomous --channels proj,agents")
	reg, err := register(s, sec, "name=ops-1;trusted=alice,bob,ghost,alice,carol,dave,erin")
	if err != nil {
		t.Fatal(err)
	}
	if reg.Owner != "alice" || reg.Credential == "" || reg.Agent.Username != "bot-x-ops-1" {
		t.Fatalf("registration: %+v", reg)
	}
	if f.bound[reg.Agent.ID] != "u-alice" {
		t.Fatalf("assign_bot: bound %v", f.bound)
	}
	// MaxTrusted 3: alice, bob checked, ghost left out, carol checked; dave and erin are cut.
	want := "for @alice · autonomous · trusts @alice, @bob, @carol +2 · via agent-registrar"
	if got := f.profiles["bot-x-ops-1"]; got != want {
		t.Fatalf("description:\n got  %q\n want %q", got, want)
	}
	if got := strings.Join(f.joined[reg.Agent.ID], ","); got != "proj,agents" {
		t.Fatalf("joined %s", got)
	}
	if tok, _ := s.Store.Lookup(sec); tok.LastUsedAt == nil || s.Store.LiveAgents(id) != 1 {
		t.Fatalf("token use not recorded: %+v", tok)
	}
	// responsible naming the owner is fine, case and @ aside.
	if _, err := register(s, sec, "name=ops-2;responsible=@Alice"); err != nil {
		t.Fatal(err)
	}
}

func TestEnrollmentFailsWhenBindingFails(t *testing.T) {
	f := newFake()
	f.failBind = true
	s, _ := newService(t, f, "")
	sec, _ := mint(t, s, alice, "")
	if _, err := register(s, sec, "name=ops-1"); !errors.Is(err, ErrUpstream) {
		t.Fatalf("want upstream error, got %v", err)
	}
	if !f.revoked["bot-bot-x-ops-1"] {
		t.Fatal("a bot whose owner could not be bound must be revoked")
	}
}

func TestEnrollmentScope(t *testing.T) {
	f := newFake()
	s, _ := newService(t, f, "")
	sec, _ := mint(t, s, alice, "--max-bots 1 --channels proj")
	for body, want := range map[string]string{
		"name=a-1;responsible=bob":   "not the token's owner",
		"name=a-1;kind=autonomous":   "allows kind session only",
		"name=a-1;channels=agents":   "does not allow channel agents",
		"name=a-1;channels=Bad Name": "invalid channel name",
	} {
		if _, err := register(s, sec, body); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: want %q, got %v", body, want, err)
		}
	}
	reg, err := register(s, sec, "name=a-1")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.joined[reg.Agent.ID], ","); got != "proj" {
		t.Fatalf("joined %s", got)
	}
	if _, err := register(s, sec, "name=a-2"); !errors.Is(err, ErrForbidden) || !strings.Contains(err.Error(), "unregister one first") {
		t.Fatalf("max bots: %v", err)
	}
	// Unregistering frees the slot.
	if err := s.Unregister(context.Background(), sec, "a-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := register(s, sec, "name=a-2"); err != nil {
		t.Fatalf("after unregister: %v", err)
	}
}

func TestEnrollmentChecksTheOwnersChannelAccessAgain(t *testing.T) {
	f := newFake()
	s, _ := newService(t, f, "")
	sec, _ := mint(t, s, alice, "--channels proj")
	// Alice leaves the private channel after creating the token.
	delete(f.members["proj"], "u-alice")
	if _, err := register(s, sec, "name=a-1"); !errors.Is(err, ErrForbidden) || !strings.Contains(err.Error(), "no access to channel proj") {
		t.Fatalf("want refusal, got %v", err)
	}
	// Alice is deactivated: her tokens stop working.
	delete(f.humans, "alice")
	if _, err := register(s, sec, "name=a-2"); !errors.Is(err, ErrForbidden) || !strings.Contains(err.Error(), "no longer an active user") {
		t.Fatalf("deactivated owner: %v", err)
	}
}

func TestSharedSecretBotsAreUnbound(t *testing.T) {
	f := newFake()
	s, _ := newService(t, f, "")
	reg, err := register(s, "shared", "name=cursor-1;responsible=alice;kind=autonomous;trusted=alice,bob")
	if err != nil {
		t.Fatal(err)
	}
	if reg.Owner != "" || len(f.bound) != 0 {
		t.Fatalf("shared secret bound an owner: %+v %v", reg, f.bound)
	}
	want := "unbound · claims @alice · autonomous · trusts @alice, @bob · via agent-registrar"
	if got := f.profiles["bot-x-cursor-1"]; got != want {
		t.Fatalf("description:\n got  %q\n want %q", got, want)
	}
	if got := strings.Join(f.joined[reg.Agent.ID], ","); got != "agents" {
		t.Fatalf("joined %s", got)
	}
	if _, err := register(s, "shared", "name=plain-1"); err != nil {
		t.Fatal(err)
	}
	if got := f.profiles["bot-x-plain-1"]; got != "unbound · via agent-registrar" {
		t.Fatalf("plain: %q", got)
	}
	// Disabled shared secret: refused.
	s.Policy.SharedSecret = ""
	if _, err := register(s, "shared", "name=cursor-2"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("disabled shared secret: %v", err)
	}
	if err := s.Unregister(context.Background(), "shared", "cursor-1"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("disabled shared secret unregister: %v", err)
	}
}

func TestUnregisterCredentials(t *testing.T) {
	f := newFake()
	s, _ := newService(t, f, "")
	ctx := context.Background()
	sec, _ := mint(t, s, alice, "--max-bots 3")
	bobInv := Invocation{Human: Human{ID: "u-bob", Handle: "bob"}}
	bobSec, _ := mint(t, s, bobInv, "")
	reg, _ := register(s, sec, "name=a-1")
	if _, err := register(s, sec, "name=a-2"); err != nil {
		t.Fatal(err)
	}
	if err := s.Unregister(ctx, bobSec, "a-1"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("another owner's token: %v", err)
	}
	if err := s.Unregister(ctx, "wrong", "a-1"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong credential: %v", err)
	}
	if err := s.Unregister(ctx, reg.Credential, "a-1"); err != nil {
		t.Fatalf("own bot token: %v", err)
	}
	if err := s.Unregister(ctx, sec, "a-2"); err != nil {
		t.Fatalf("owner's token: %v", err)
	}
	if err := s.Unregister(ctx, sec, "a-2"); err != nil {
		t.Fatalf("idempotent: %v", err)
	}
	if s.Store.LiveAgents(regToken(t, s, sec)) != 0 {
		t.Fatal("unregistered agents still count")
	}
}

func regToken(t *testing.T, s *Service, sec string) string {
	t.Helper()
	tok, ok := s.Store.Lookup(sec)
	if !ok {
		t.Fatal("token not found")
	}
	return tok.ID
}

func TestTrustedCutWithoutWrittenNames(t *testing.T) {
	f := newFake()
	s, _ := newService(t, f, "")
	s.Policy.MaxTrusted = 0
	if _, err := register(s, "shared", "name=x-1;trusted=alice,bob"); err != nil {
		t.Fatal(err)
	}
	if got := f.profiles["bot-x-x-1"]; got != "unbound · trusts @ +2 · via agent-registrar" {
		t.Fatalf("got %q", got)
	}
}

func TestSplitArgsAndTTL(t *testing.T) {
	got, err := splitArgs(`create --label "two words" --kind 'session'`)
	if err != nil || strings.Join(got, "|") != "create|--label|two words|--kind|session" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := splitArgs(`create --label "open`); err == nil {
		t.Fatal("unclosed quote accepted")
	}
	for in, want := range map[string]time.Duration{"30d": 720 * time.Hour, "2w": 336 * time.Hour, "12h": 12 * time.Hour} {
		if d, err := parseTTL(in); err != nil || d != want {
			t.Fatalf("%s: %v %v", in, d, err)
		}
	}
}

// The protocol must not depend on a provider's client.
func TestCoreImportsNoProvider(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, name := range files {
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			if strings.Contains(imp.Path.Value, "/internal/") {
				t.Errorf("%s imports %s", name, imp.Path.Value)
			}
		}
	}
}
