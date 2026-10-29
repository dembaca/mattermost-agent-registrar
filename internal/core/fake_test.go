package core

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"
)

// fakeProvider is an in-memory ProviderPort: humans, channels with members,
// and a log of what the protocol asked it to do.
type fakeProvider struct {
	mu       sync.Mutex
	humans   map[string]Human           // by handle
	public   map[string]bool            // channel name -> public
	members  map[string]map[string]bool // channel -> human ids
	team     map[string]bool            // human ids in the team
	agents   map[string]Agent           // by username
	creds    map[string]string          // credential -> agent id
	profiles map[string]string          // username -> description
	bound    map[string]string          // agent id -> owner id
	joined   map[string][]string        // agent id -> channels
	revoked  map[string]bool            // agent id
	failBind bool
	next     int
}

func newFake() *fakeProvider {
	return &fakeProvider{
		humans: map[string]Human{
			"alice": {ID: "u-alice", Handle: "alice"},
			"bob":   {ID: "u-bob", Handle: "bob"},
			"carol": {ID: "u-carol", Handle: "carol"},
		},
		public:   map[string]bool{"agents": true, "proj": false, "open": true},
		members:  map[string]map[string]bool{"proj": {"u-alice": true}},
		team:     map[string]bool{"u-alice": true, "u-bob": true},
		agents:   map[string]Agent{},
		creds:    map[string]string{},
		profiles: map[string]string{},
		bound:    map[string]string{},
		joined:   map[string][]string{},
		revoked:  map[string]bool{},
	}
}

var _ ProviderPort = (*fakeProvider)(nil)

func (f *fakeProvider) VerifyInvocation(*http.Request) (Invocation, error) {
	return Invocation{}, errors.New("not used")
}
func (f *fakeProvider) ReplyPrivate(http.ResponseWriter, Invocation, string) {}

func (f *fakeProvider) ResolveHuman(_ context.Context, handle string) (*Human, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if h, ok := f.humans[handle]; ok {
		return &h, nil
	}
	return nil, nil
}

func (f *fakeProvider) HumanByID(_ context.Context, id string) (*Human, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, h := range f.humans {
		if h.ID == id {
			h := h
			return &h, nil
		}
	}
	return nil, nil
}

func (f *fakeProvider) HumanCanAccess(_ context.Context, h Human, ch string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pub, ok := f.public[ch]
	if !ok {
		return false, ErrNoSuchChannel
	}
	if !f.team[h.ID] {
		return false, nil
	}
	return f.members[ch][h.ID] || pub, nil
}

func (f *fakeProvider) FindAgent(_ context.Context, username string) (*Agent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a, ok := f.agents[username]; ok {
		return &a, nil
	}
	return nil, nil
}

func (f *fakeProvider) AgentForCredential(_ context.Context, cred string) (*Agent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.creds[cred]
	if !ok {
		return nil, errors.New("401")
	}
	for _, a := range f.agents {
		if a.ID == id {
			return &a, nil
		}
	}
	return nil, errors.New("gone")
}

func (f *fakeProvider) CreateAgent(_ context.Context, username, _, profile string) (Agent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	a := Agent{ID: "bot-" + username, Username: username}
	f.agents[username] = a
	f.profiles[username] = profile
	return a, nil
}

func (f *fakeProvider) BindOwner(_ context.Context, a Agent, owner Human) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failBind {
		return errors.New("403 assign_bot")
	}
	f.bound[a.ID] = owner.ID
	return nil
}

func (f *fakeProvider) IssueCredential(_ context.Context, a Agent) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := "cred-" + a.ID
	f.creds[c] = a.ID
	return c, nil
}

func (f *fakeProvider) JoinChannels(_ context.Context, a Agent, chans []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.joined[a.ID] = append([]string(nil), chans...)
	return nil
}

func (f *fakeProvider) RevokeAgent(_ context.Context, a Agent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked[a.ID] = true
	delete(f.agents, a.Username)
	return nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newService(t *testing.T, f *fakeProvider, storePath string) (*Service, *clock) {
	t.Helper()
	st, err := OpenStore(storePath, []byte("pepper-pepper-pepper-pepper-pepper"))
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)}
	return &Service{
		Provider: f,
		Store:    st,
		Policy: Policy{
			BotPrefix: "bot-x-", DefaultChannel: "agents", SharedSecret: "shared",
			MaxTrusted: 3, DefaultTTL: 30 * 24 * time.Hour, MaxTTL: 90 * 24 * time.Hour,
			DefaultMaxBots: 2, MaxBotsLimit: 5, MaxTokensPerUser: 3,
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: c.now,
	}, c
}
